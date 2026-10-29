package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"sync"
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

	mu        sync.Mutex
	endpoints map[string]engine.EndpointStatus // the last status line
}

// endpointStatus returns the last status the engine reported for its
// endpoint lines.
func (p *engineProc) endpointStatus() map[string]engine.EndpointStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.endpoints)
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
	// Pipes of our own for stdout and stderr: Wait would close pipes it
	// made as soon as the engine exits and lose the end of its log, the
	// part a crash writes. These are read to the end on their own.
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		outR.Close()
		outW.Close()
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = outW, errW
	err = cmd.Start()
	outW.Close()
	errW.Close()
	if err != nil {
		outR.Close()
		errR.Close()
		return nil, fmt.Errorf("引擎起不来：%w", err)
	}
	p := &engineProc{cmd: cmd, pid: cmd.Process.Pid, stdin: stdin, done: make(chan struct{})}
	logPath := d.opts.Layout.EngineLog()
	go func() {
		defer errR.Close()
		scanner := bufio.NewScanner(errR)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			appendRotating(logPath, []byte(scrub.scrub(scanner.Text())+"\n"))
		}
	}()
	ready := make(chan engine.Ready, 1)
	go func() {
		defer outR.Close()
		reader := bufio.NewReaderSize(outR, 64<<10)
		line, _ := reader.ReadSlice('\n')
		var r engine.Ready
		_ = json.Unmarshal(line, &r)
		ready <- r
		// Then status lines, one per change, 6.3. A line longer than
		// maxStatusLine is skipped to its end and reading goes on.
		for {
			line, err := readLine(reader, maxStatusLine)
			if err != nil {
				break
			}
			var status engine.StatusLine
			if line == nil || json.Unmarshal(line, &status) != nil {
				continue
			}
			scrubEndpoints(status.Endpoints, scrub)
			p.mu.Lock()
			previous := p.endpoints
			p.endpoints = status.Endpoints
			p.mu.Unlock()
			d.endpointsChanged(previous, status.Endpoints)
		}
		_, _ = io.Copy(io.Discard, outR)
	}()
	go func() {
		_ = cmd.Wait()
		_ = stdin.Close()
		close(p.done)
	}()
	// The configuration goes in as one JSON value; stdin then stays open
	// until the engine stops, so the engine notices if the daemon dies. An
	// engine that does not read it is killed when readyTimeout runs out,
	// which ends the write too.
	written := make(chan error, 1)
	go func() {
		_, err := stdin.Write(compiled)
		written <- err
	}()
	var reason string
	timeout := time.After(readyTimeout)
	select {
	case err := <-written:
		if err != nil {
			reason = fmt.Sprintf("交给引擎配置时出错：%v", err)
			break
		}
		select {
		case r := <-ready:
			reason = readyReason(r, scrub)
			if reason == "" {
				return p, nil
			}
		case <-timeout:
			reason = fmt.Sprintf("引擎 %s 内没有就绪", readyTimeout)
		}
	case <-timeout:
		reason = fmt.Sprintf("引擎 %s 内没有读完配置", readyTimeout)
	}
	p.stop()
	return nil, errors.New(reason)
}

// readyReason is why a ready line does not let the engine run, or "".
func readyReason(r engine.Ready, scrub *scrubber) string {
	switch {
	case r.Ready && r.Version == buildinfo.Build():
		return ""
	case r.Ready:
		return fmt.Sprintf("引擎是 %s，不是 daemon 的 %s；重新 sudo xdial daemon install", r.Version, buildinfo.Build())
	case r.Error != "":
		return "引擎没能启动：" + scrub.scrub(r.Error)
	default:
		return "引擎没有报告就绪就退出了，原因在引擎日志里"
	}
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

// scrubEndpoints scrubs what a VPN server says, which reaches status and
// the event log, as the engine's log is, 4.3, and then cuts it to
// maxEndpointText bytes: cutting first could leave part of a secret the
// scrubber no longer recognizes.
func scrubEndpoints(endpoints map[string]engine.EndpointStatus, scrub *scrubber) {
	for id, e := range endpoints {
		e.Error = scrubText(e.Error, scrub)
		e.AuthMessage = scrubText(e.AuthMessage, scrub)
		endpoints[id] = e
	}
}

// scrubText scrubs one text and cuts it to maxEndpointText bytes. A text
// the engine cut short may end in part of a secret, which scrubbing does
// not recognize and which replacing the secrets before it can move into
// what is kept; its last bytes, as many as the longest secret takes, are
// dropped after scrubbing.
func scrubText(s string, scrub *scrubber) string {
	cut := strings.HasSuffix(s, engine.TruncatedMark)
	s = scrub.scrub(strings.TrimSuffix(s, engine.TruncatedMark))
	if cut {
		s = s[:max(0, len(s)-scrub.longest)]
		s = strings.ToValidUTF8(s, "") + "…"
	}
	return cutText(s)
}

// maxEndpointText bounds a VPN server's text in status and events.
const maxEndpointText = 512

func cutText(s string) string {
	if len(s) <= maxEndpointText {
		return s
	}
	return strings.ToValidUTF8(s[:maxEndpointText], "") + "…"
}

// maxStatusLine bounds one status line from the engine.
const maxStatusLine = 1 << 20

// readLine reads one line of at most limit bytes. A longer line is read to
// its end and returned as nil, so one bad line costs only itself.
func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > limit {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		switch {
		case err == bufio.ErrBufferFull:
			continue
		case err != nil:
			return nil, err
		case tooLong:
			return nil, nil
		default:
			return line, nil
		}
	}
}

// endpointsChanged records an event for each endpoint whose state changed.
// The tailscale login link stays out of the event log; status shows it.
func (d *Daemon) endpointsChanged(previous, current map[string]engine.EndpointStatus) {
	ids := make([]string, 0, len(current))
	for id := range current {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		now, before := current[id], previous[id]
		if now.State == before.State && now.Error == before.Error && slices.Equal(now.DefaultRoute, before.DefaultRoute) {
			continue
		}
		fields := map[string]any{"line": id, "type": now.Type, "state": now.State}
		if now.Error != "" {
			fields["error"] = now.Error
		}
		if now.AuthMessage != "" {
			fields["auth_message"] = now.AuthMessage
		}
		if len(now.DefaultRoute) > 0 {
			fields["default_route"] = now.DefaultRoute
		}
		d.events.add("endpoint_state", fields)
	}
}
