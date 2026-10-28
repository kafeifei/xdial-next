package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"syscall"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
	"github.com/kafeifei/xdial-next/internal/sysdns"
)

// Supervision, ARCHITECTURE.md 6.3.
const (
	readyTimeout = 20 * time.Second
	stopTimeout  = 5 * time.Second
	failWindow   = 5 * time.Minute
	maxFailures  = 5
)

type engineProc struct {
	cmd   *exec.Cmd
	pid   int
	stdin io.WriteCloser // held open for the engine's life, 6.3
	done  chan struct{}
	err   error
}

// startEngine starts the engine child with a compiled configuration on its
// stdin and waits for it to report ready. Its stderr is scrubbed into the
// engine log; none of it reaches a caller.
func (d *Daemon) startEngine(compiled []byte) (*engineProc, error) {
	cmd := exec.Command(d.opts.Executable, engine.EngineCommand, d.opts.Layout.Tailscale())
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
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
		return nil, fmt.Errorf("起不来：%w", err)
	}
	p := &engineProc{cmd: cmd, pid: cmd.Process.Pid, stdin: stdin, done: make(chan struct{})}
	scrub := newScrubber(d.secrets)
	logPath := d.opts.Layout.EngineLog()
	go func() {
		scanner := bufio.NewScanner(stderr)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			appendRotating(logPath, []byte(scrub.scrub(scanner.Text())+"\n"))
		}
	}()
	ready := make(chan bool, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadBytes('\n')
		var r engine.Ready
		ready <- err == nil && json.Unmarshal(line, &r) == nil && r.Ready
		_, _ = io.Copy(io.Discard, stdout)
	}()
	go func() {
		p.err = cmd.Wait()
		_ = stdin.Close()
		close(p.done)
	}()
	// The configuration goes in as one JSON value; stdin then stays open
	// until the engine stops, so the engine notices if the daemon dies.
	_, werr := stdin.Write(compiled)
	if werr != nil {
		p.stop()
		return nil, fmt.Errorf("交配置时出错：%w", werr)
	}
	select {
	case ok := <-ready:
		if ok {
			return p, nil
		}
	case <-time.After(readyTimeout):
	case <-p.done:
	}
	p.stop()
	return nil, errors.New("没能启动，原因写在引擎日志里")
}

// stop asks the engine to exit and kills it if it does not.
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

// usedSecrets reports the secrets a compilation needs that are not set,
// and checks the ones that are against the fields that use them, without
// ever echoing a value.
func (d *Daemon) checkSecrets(used []string) error {
	var missing []string
	for _, name := range used {
		if _, ok := d.secrets[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return cli.Errorf(cli.CodeSecretMissing, "用 xdial secret set <名字> 设置", "还没设置的凭据：%v", missing)
	}
	return d.checkFormats(d.cfg, func(name string) (string, bool) {
		s, ok := d.secrets[name]
		return s.Value, ok
	})
}

func (d *Daemon) checkFormats(c *config.Config, value func(string) (string, bool)) error {
	var problems []cli.Problem
	for _, use := range c.Secrets {
		v, ok := value(use.Name)
		if !ok || use.Spec.Format == nil {
			continue
		}
		if msg := use.Spec.Format(v, use.Parent); msg != "" {
			problems = append(problems, cli.Problem{Code: cli.CodeConfigValue, Path: use.Path, Object: use.Object, Message: "凭据 " + use.Name + " 的格式不对：" + msg})
		}
	}
	if len(problems) > 0 {
		return &cli.Error{Code: cli.CodeSecretFormat, Message: fmt.Sprintf("%d 处凭据格式不对", len(problems)), Problems: problems}
	}
	return nil
}

// connectLocked compiles a scenario with the real secrets, starts the
// engine and then points the system resolver into TUN, 6.3.
func (d *Daemon) connectLocked(scenario string) error {
	if d.cfg == nil {
		return cli.Errorf(cli.CodeConfigInvalid, "先用 xdial config apply 提交配置", "还没有配置")
	}
	if scenario == "" && len(d.cfg.Scenarios) > 0 {
		scenario = d.cfg.Scenarios[0].ID
	}
	found := false
	for _, s := range d.cfg.Scenarios {
		found = found || s.ID == scenario
	}
	if !found {
		return cli.Errorf(cli.CodeConfigConflict, "用 xdial scenario use <id> 选一个存在的场景", "场景 %q 不存在", scenario)
	}
	opts := engine.Options{
		Scenario: scenario, TUN: !d.opts.NoTUN, Stack: engine.DefaultStack, StateDirectory: d.opts.Layout.Tailscale(),
		Secret: func(u config.SecretUse) string { return d.secrets[u.Name].Value },
	}
	result, err := engine.Compile(d.cfg, opts)
	if err != nil {
		return cli.Errorf(cli.CodeInternal, "", "编译失败：%v", err)
	}
	if err := d.checkSecrets(result.Secrets); err != nil {
		return err
	}
	d.teardownLocked()
	d.setStatus("connecting", "")
	p, err := d.startEngine(result.JSON)
	if err != nil {
		d.setStatus("failed", "引擎"+err.Error())
		d.events.add("engine_failed", map[string]any{"scenario": scenario})
		return cli.Errorf(cli.CodeEngineFailed, "看 xdial status；引擎日志在 daemon 的 private 目录", "引擎%v", err)
	}
	d.engine = p
	d.events.add("engine_started", map[string]any{"scenario": scenario, "pid": p.pid})
	if err := d.opts.SetDNS(d.opts.Layout.DNSKey(), netip.MustParseAddr(sysdns.Server)); err != nil {
		d.teardownLocked()
		d.setStatus("failed", "设置系统 DNS 失败")
		d.events.add("dns_set_failed", map[string]any{"error": err.Error()})
		return cli.Errorf(cli.CodeEngineFailed, "", "设置系统 DNS 失败：%v", err)
	}
	d.dnsSet = true
	d.events.add("dns_set", nil)
	d.state.Scenario, d.state.Connected = scenario, true
	if err := d.saveState(); err != nil {
		d.events.add("state_save_failed", map[string]any{"error": err.Error()})
	}
	d.setStatus("connected", "")
	go d.watch(p)
	return nil
}

// teardownLocked clears the resolver before stopping the engine, so the
// system never points at a resolver that is gone, 6.3.
func (d *Daemon) teardownLocked() {
	if d.dnsSet || d.engine != nil {
		if err := d.opts.ClearDNS(d.opts.Layout.DNSKey()); err != nil {
			d.events.add("dns_clear_failed", map[string]any{"error": err.Error()})
		} else if d.dnsSet {
			d.events.add("dns_cleared", nil)
		}
		d.dnsSet = false
	}
	if p := d.engine; p != nil {
		d.engine = nil
		d.mu.Unlock()
		p.stop()
		d.mu.Lock()
		d.events.add("engine_stopped", map[string]any{"pid": p.pid})
	}
}

// watch handles an engine that exits on its own: the resolver goes first,
// then restarts back off, and five failures in five minutes stop them.
func (d *Daemon) watch(p *engineProc) {
	<-p.done
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.engine != p || d.closing {
		return
	}
	d.engine = nil
	d.teardownLocked()
	now := time.Now()
	d.failures = append(d.failures, now)
	for len(d.failures) > 0 && now.Sub(d.failures[0]) > failWindow {
		d.failures = d.failures[1:]
	}
	d.events.add("engine_exited", map[string]any{"pid": p.pid, "failures": len(d.failures)})
	if len(d.failures) >= maxFailures {
		d.setStatus("failed", fmt.Sprintf("引擎 %s 内退出了 %d 次，已停止重连", failWindow, len(d.failures)))
		return
	}
	backoff := time.Duration(1<<(len(d.failures)-1)) * time.Second
	d.setStatus("connecting", "引擎意外退出，正在重连")
	time.AfterFunc(backoff, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.closing || !d.state.Connected || d.engine != nil {
			return
		}
		if err := d.connectLocked(d.state.Scenario); err != nil {
			d.lastErr = err.Error()
		}
	})
}
