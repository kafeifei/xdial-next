package daemon

import (
	"encoding/json"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/engine"
)

// Tailscale login and logout, ARCHITECTURE.md 3.5 and 4.7.
const (
	SchemaTailscale = "xdial.tailscale/v1"
	// loginWait bounds how long a login waits for the line's state.
	loginWait = 20 * time.Second
)

// TailscaleResult is what tailscale login and logout return: the line's
// state as the engine last reported it.
type TailscaleResult struct {
	Line string `json:"line"`
	engine.EndpointStatus
}

// tailscaleLine checks that line is a tailscale line of the running
// connection: login and logout act on the engine, so a line the current
// scenario does not reach has nothing to log in, 3.5.
func (d *Daemon) tailscaleLine(line string) (*connection, error) {
	d.mu.Lock()
	cfg, c := d.cfg, d.conn
	d.mu.Unlock()
	if cfg == nil || cfg.Line(line) == nil || cfg.Line(line).Type != "tailscale" {
		return nil, cli.Errorf(cli.CodeConfigConflict, "用 xdial config export 查看有哪些线路", "%q 不是 tailscale 线路", line)
	}
	if c == nil {
		return nil, cli.Errorf(cli.CodeConfigConflict, "先 xdial connect 到用到这条线路的场景", "还没有连接")
	}
	if _, ok := c.engine.endpointStatus()[line]; !ok {
		return nil, cli.Errorf(cli.CodeConfigConflict, "先切到用到这条线路的场景", "当前场景 %s 用不到线路 %s", c.scenario, line)
	}
	return c, nil
}

// waitLine waits until line's state satisfies done or loginWait runs out,
// and returns the last state seen.
func (d *Daemon) waitLine(line string, done func(engine.EndpointStatus) bool) TailscaleResult {
	deadline := time.Now().Add(loginWait)
	for {
		d.mu.Lock()
		c := d.conn
		d.mu.Unlock()
		s := engine.EndpointStatus{Type: "tailscale", State: "connecting"}
		if c != nil {
			if reported, ok := c.engine.endpointStatus()[line]; ok {
				s = reported
			}
		}
		if done(s) || time.Now().After(deadline) {
			return TailscaleResult{Line: line, EndpointStatus: s}
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// tailscaleLogin logs a tailscale line of the connection in. With an auth
// key the engine is reloaded once with the key compiled into that line,
// and the key is kept nowhere, 4.7; without one it returns the login link
// the line waits on.
func (d *Daemon) tailscaleLogin(params json.RawMessage) reply {
	var p struct {
		Line    string `json:"line"`
		AuthKey string `json:"auth_key"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	if p.AuthKey == "" {
		if _, err := d.tailscaleLine(p.Line); err != nil {
			return reply{err: err}
		}
		r := d.waitLine(p.Line, func(s engine.EndpointStatus) bool { return s.State == "connected" || s.AuthURL != "" })
		return reply{schema: SchemaTailscale, result: r}
	}
	d.ctl.Lock()
	c, err := d.tailscaleLine(p.Line)
	if err != nil {
		d.ctl.Unlock()
		return reply{err: err}
	}
	d.mu.Lock()
	cfg := d.cfg
	d.mu.Unlock()
	next, err := d.prepareLogin(cfg, c.scenario, map[string]string{p.Line: p.AuthKey})
	if err == nil {
		d.gen++
		err = d.bringUp(next)
	}
	d.ctl.Unlock()
	if err != nil {
		return reply{err: err}
	}
	d.events.add("tailscale_login", map[string]any{"line": p.Line})
	r := d.waitLine(p.Line, func(s engine.EndpointStatus) bool { return s.State == "connected" || s.State == "failed" })
	return reply{schema: SchemaTailscale, result: r}
}

// tailscaleLogout logs a tailscale line of the connection out through the
// engine; the line then waits for a new login.
func (d *Daemon) tailscaleLogout(params json.RawMessage) reply {
	var p struct {
		Line string `json:"line"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	c, err := d.tailscaleLine(p.Line)
	if err != nil {
		return reply{err: err}
	}
	if err := c.engine.send(engine.Command{TailscaleLogout: p.Line}); err != nil {
		return reply{err: cli.Errorf(cli.CodeEngineFailed, "", "引擎没有收到登出命令：%v", err)}
	}
	d.events.add("tailscale_logout", map[string]any{"line": p.Line})
	r := d.waitLine(p.Line, func(s engine.EndpointStatus) bool { return s.State == "auth_required" })
	return reply{schema: SchemaTailscale, result: r}
}
