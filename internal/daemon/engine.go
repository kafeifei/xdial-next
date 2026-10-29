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
	"regexp"
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
	endpoints map[string]engine.EndpointStatus // the last snapshot
	groups    map[string]engine.GroupStatus
	tests     map[int]chan engine.TestResult // url_test commands waiting, by id
	nextTest  int
	stdinMu   sync.Mutex // commands, one at a time
}

// groupStatus returns the last status the engine reported for its groups.
func (p *engineProc) groupStatus() map[string]engine.GroupStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.groups)
}

// urlTest asks the engine to test tags and waits for the answer.
func (p *engineProc) urlTest(tags []string, timeout time.Duration) (engine.TestResult, error) {
	p.mu.Lock()
	p.nextTest++
	id := p.nextTest
	if p.tests == nil {
		p.tests = map[int]chan engine.TestResult{}
	}
	answer := make(chan engine.TestResult, 1)
	p.tests[id] = answer
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.tests, id)
		p.mu.Unlock()
	}()
	if err := p.send(engine.Command{URLTest: &engine.URLTestCommand{ID: id, Tags: tags}}); err != nil {
		return engine.TestResult{}, err
	}
	select {
	case r := <-answer:
		return r, nil
	case <-p.done:
		return engine.TestResult{}, errors.New("引擎退出了")
	case <-time.After(timeout):
		return engine.TestResult{}, errors.New("测速超时")
	}
}

// send writes one command to the engine's stdin, 6.3.
func (p *engineProc) send(c engine.Command) error {
	line, err := json.Marshal(c)
	if err != nil {
		return err
	}
	p.stdinMu.Lock()
	defer p.stdinMu.Unlock()
	_, err = p.stdin.Write(append(line, '\n'))
	return err
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
			// Login links go first: scrubbing could break up the words the
			// pattern looks for.
			appendRotating(logPath, []byte(scrub.scrub(withoutLoginLinks(scanner.Text()))+"\n"))
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
			if t := status.Test; t != nil {
				p.mu.Lock()
				waiter := p.tests[t.ID]
				p.mu.Unlock()
				if waiter != nil {
					waiter <- *t
				}
				continue
			}
			scrubEndpoints(status.Endpoints, scrub)
			p.mu.Lock()
			previous := p.endpoints
			p.endpoints, p.groups = status.Endpoints, status.Groups
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

// loginLink is sing-box's log line for a tailscale line waiting to log
// in. The link logs whoever opens it into the account they choose, so it
// stays out of the log; status has it, 3.5.
var loginLink = regexp.MustCompile(`(Waiting for authentication: )\S+`)

func withoutLoginLinks(line string) string {
	return loginLink.ReplaceAllString(line, "${1}<登录链接见 xdial status>")
}

// scrubEndpoints bounds and scrubs what a VPN server says, which reaches
// status and the event log, as the engine's log is, 4.3.
func scrubEndpoints(endpoints map[string]engine.EndpointStatus, scrub *scrubber) {
	for id, e := range endpoints {
		e.Error = scrubText(e.Error, scrub)
		e.AuthMessage = scrubText(e.AuthMessage, scrub)
		endpoints[id] = e
	}
}

// scrubText keeps at most maxEndpointText bytes of a VPN server's text.
// It cuts the original first, where no secret is split, then masks: every
// secret in what is kept is whole and masked whole. Masking first and
// cutting after would not do, since masking changes the length before the
// cut. Masks can be longer than what they hide, so the masked text is cut
// once more, which can only shorten a mask.
func scrubText(s string, scrub *scrubber) string {
	cut := scrub.safeCut(s, maxEndpointText)
	kept := scrub.scrub(s[:cut])
	long := len(kept) > maxEndpointText
	if long {
		kept = strings.ToValidUTF8(kept[:maxEndpointText], "")
	}
	if cut < len(s) || long {
		kept += "…"
	}
	return kept
}

// maxEndpointText bounds a VPN server's text in status and events.
const maxEndpointText = 512

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
