package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/kafeifei/xdial-next/internal/buildinfo"
	"github.com/kafeifei/xdial-next/internal/engine"
)

// Supervision, ARCHITECTURE.md 6.3.
const (
	readyTimeout = 20 * time.Second
	stopTimeout  = 5 * time.Second
)

type engineProc struct {
	cmd   *exec.Cmd
	pid   int
	stdin io.WriteCloser // held open for the engine's life, 6.3
	done  chan struct{}
}

// startEngine starts the engine child with a compiled configuration on its
// stdin and waits for its one line on stdout: ready, from the same build as
// the daemon, or why not. The child inherits lock, 6.1. Its stderr is
// scrubbed into the engine log; what reaches a caller is scrubbed too.
func (d *Daemon) startEngine(compiled []byte, lock *os.File, scrub *scrubber) (*engineProc, error) {
	cmd := exec.Command(d.opts.Executable, engine.EngineCommand, d.opts.Layout.Tailscale())
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.ExtraFiles = []*os.File{lock}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("引擎起不来：%w", err)
	}
	p := &engineProc{cmd: cmd, pid: cmd.Process.Pid, stdin: stdin, done: make(chan struct{})}
	logPath := d.opts.Layout.EngineLog()
	go func() {
		scanner := bufio.NewScanner(stderr)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			appendRotating(logPath, []byte(scrub.scrub(scanner.Text())+"\n"))
		}
	}()
	ready := make(chan engine.Ready, 1)
	go func() {
		line, _ := bufio.NewReader(io.LimitReader(stdout, 64<<10)).ReadBytes('\n')
		var r engine.Ready
		_ = json.Unmarshal(line, &r)
		ready <- r
		_, _ = io.Copy(io.Discard, stdout)
	}()
	go func() {
		_ = cmd.Wait()
		_ = stdin.Close()
		close(p.done)
	}()
	// The configuration goes in as one JSON value; stdin then stays open
	// until the engine stops, so the engine notices if the daemon dies.
	if _, err := stdin.Write(compiled); err != nil {
		p.stop()
		return nil, fmt.Errorf("交给引擎配置时出错：%w", err)
	}
	var reason string
	select {
	case r := <-ready:
		switch {
		case r.Ready && r.Version == buildinfo.Build():
			return p, nil
		case r.Ready:
			reason = fmt.Sprintf("引擎是 %s，不是 daemon 的 %s；重新 sudo xdial daemon install", r.Version, buildinfo.Build())
		case r.Error != "":
			reason = "引擎没能启动：" + scrub.scrub(r.Error)
		default:
			reason = "引擎没有报告就绪就退出了，原因在引擎日志里"
		}
	case <-time.After(readyTimeout):
		reason = fmt.Sprintf("引擎 %s 内没有就绪", readyTimeout)
	}
	p.stop()
	return nil, errors.New(reason)
}

// stop asks the engine to exit and kills it if it does not, then waits.
func (p *engineProc) stop() {
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(stopTimeout):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}
