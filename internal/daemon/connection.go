package daemon

import (
	"fmt"
	"maps"
	"net/netip"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
)

// Connection control, ARCHITECTURE.md 6.3. Every step that starts, stops or
// replaces the connection runs under d.ctl, one at a time: user requests,
// reloads, retries after a crash and the periodic checks. A retry carries
// the generation it was scheduled in and is dropped if a user request came
// since.
const (
	failWindow    = 5 * time.Minute
	maxFailures   = 5
	probeTimeout  = 5 * time.Second
	checkInterval = 15 * time.Second
	settleDelay   = time.Second
	maxProbeMiss  = 3
)

// connection is what a connected daemon holds, torn down in reverse.
type connection struct {
	scenario  string
	revision  string
	physical  []netip.Addr
	lock      *connectionLock
	engine    *engineProc
	resolver  Resolver
	first     string // the system's first resolver, last checked
	probeMiss int
}

// connectLocked brings up scenario with the current configuration,
// replacing any connection, 6.3: compile with the real secrets and the
// physical DNS, take the connection lock, start the engine, check through
// TUN that queries reach sing-box, and only then publish the resolver key.
// Between the old connection going and the new one coming up, traffic goes
// direct. Callers hold d.ctl.
func (d *Daemon) connectLocked(scenario string) error {
	d.mu.Lock()
	cfg, secrets := d.cfg, maps.Clone(d.secrets)
	d.mu.Unlock()
	if cfg == nil {
		return cli.Errorf(cli.CodeConfigInvalid, "先用 xdial config apply 提交配置", "还没有配置")
	}
	if scenario == "" && len(cfg.Scenarios) > 0 {
		scenario = cfg.Scenarios[0].ID
	}
	found := false
	for _, s := range cfg.Scenarios {
		found = found || s.ID == scenario
	}
	if !found {
		return cli.Errorf(cli.CodeConfigConflict, "用 xdial scenario use <id> 选一个存在的场景", "场景 %q 不存在", scenario)
	}
	physical, err := d.sys.PhysicalDNS()
	if err != nil {
		return d.failLocked(fmt.Sprintf("读不到物理网络的 DNS：%v", err))
	}
	physical = usablePhysical(physical)
	d.mu.Lock()
	d.physical = physical
	d.mu.Unlock()
	if len(physical) == 0 {
		return d.failLocked("物理网络还没有 DNS 服务器，网络就绪后自动重试")
	}
	opts := engine.Options{
		Scenario: scenario, TUN: !d.opts.NoTUN, Stack: engine.DefaultStack, StateDirectory: d.opts.Layout.Tailscale(),
		PhysicalDNS: physical[0],
		Secret:      func(u config.SecretUse) string { return secrets[u.Name].Value },
	}
	result, err := engine.Compile(cfg, opts)
	if err != nil {
		return cli.Errorf(cli.CodeInternal, "", "编译失败：%v", err)
	}
	if err := checkSecrets(cfg, secrets, result.Secrets); err != nil {
		return err
	}

	d.disconnectLocked()
	d.setStatus("connecting", "")
	c := &connection{scenario: scenario, revision: cfg.Root.Revision(), physical: physical}
	// Busy means the other identity is connected, or, right after a
	// restart, this daemon's previous engine is still exiting; retries
	// cover the latter.
	c.lock, err = acquireConnectionLock(d.opts.Layout.ConnectionLock())
	if err != nil {
		d.setStatus("failed", err.Error())
		return err
	}
	c.engine, err = d.startEngine(result.JSON, c.lock.file, newScrubber(secrets))
	if err != nil {
		c.lock.release()
		d.events.add("engine_failed", map[string]any{"scenario": scenario})
		return d.failLocked(err.Error())
	}
	d.events.add("engine_started", map[string]any{"scenario": scenario, "pid": c.engine.pid})
	if err := d.probe(); err != nil {
		d.teardown(c)
		return d.failLocked("查询进不了 sing-box：" + err.Error())
	}
	c.resolver, err = d.sys.Hold(d.opts.Layout.DNSKey(), c.lock.file)
	if err != nil {
		d.teardown(c)
		return d.failLocked("设置系统 DNS 失败：" + err.Error())
	}
	published, first := d.checkResolver()
	if !published {
		d.teardown(c)
		return d.failLocked("系统 DNS 设置后没有生效")
	}
	c.first = first
	d.events.add("dns_set", map[string]any{"first": first, "physical": physical})

	d.mu.Lock()
	d.conn = c
	d.state.Scenario, d.state.Connected = scenario, true
	d.mu.Unlock()
	d.wakeMonitor()
	if err := d.saveState(); err != nil {
		d.events.add("state_save_failed", map[string]any{"error": err.Error()})
	}
	d.setStatus("connected", "")
	go d.watch(c.engine)
	return nil
}

func (d *Daemon) wakeMonitor() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// failLocked records why a connection attempt failed.
func (d *Daemon) failLocked(reason string) error {
	d.setStatus("failed", reason)
	return cli.Errorf(cli.CodeEngineFailed, "看 xdial status 和 xdial logs", "%s", reason)
}

// probe asks the resolver address until sing-box answers: TUN routes can
// take a moment after the engine reports ready.
func (d *Daemon) probe() error {
	deadline := time.Now().Add(probeTimeout)
	for {
		err := d.sys.Probe()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// checkResolver waits briefly for configd to take the key in and reports
// whether it is published and which resolver is first.
func (d *Daemon) checkResolver() (bool, string) {
	deadline := time.Now().Add(3 * time.Second)
	for {
		published, first, err := d.sys.Resolver(d.opts.Layout.DNSKey())
		if (published && first == resolverAddress.String()) || time.Now().After(deadline) {
			if err != nil {
				d.events.add("dns_check_failed", map[string]any{"error": err.Error()})
			}
			return published, first
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// disconnectLocked takes down the connection, if any: the resolver key
// first, so the system never points at a resolver that is gone, then the
// engine, then the lock. Callers hold d.ctl.
func (d *Daemon) disconnectLocked() {
	d.mu.Lock()
	c := d.conn
	d.conn = nil
	d.mu.Unlock()
	if c != nil {
		d.teardown(c)
	}
}

func (d *Daemon) teardown(c *connection) {
	if c.resolver != nil {
		c.resolver.Close()
		d.events.add("dns_cleared", nil)
	}
	if c.engine != nil {
		c.engine.stop()
		d.events.add("engine_stopped", map[string]any{"pid": c.engine.pid})
	}
	c.lock.release()
}

// watch handles an engine that exits on its own: the resolver key goes,
// traffic goes direct, and restarts back off, 6.3.
func (d *Daemon) watch(p *engineProc) {
	<-p.done
	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	c, closing := d.conn, d.closing
	d.mu.Unlock()
	if closing || c == nil || c.engine != p {
		return
	}
	d.gen++
	d.disconnectLocked()
	d.events.add("engine_exited", map[string]any{"pid": p.pid})
	d.retryLocked("引擎意外退出")
}

// retryLocked counts a failure and schedules the next attempt, or stops
// after maxFailures in failWindow. Until then traffic goes direct.
func (d *Daemon) retryLocked(reason string) {
	now := time.Now()
	d.failures = append(d.failures, now)
	for len(d.failures) > 0 && now.Sub(d.failures[0]) > failWindow {
		d.failures = d.failures[1:]
	}
	if len(d.failures) >= maxFailures {
		d.setStatus("failed", fmt.Sprintf("%s；%s 内失败了 %d 次，停止重连，网络变化或手动 connect 时再试", reason, failWindow, len(d.failures)))
		d.events.add("retry_stopped", map[string]any{"failures": len(d.failures)})
		return
	}
	backoff := time.Duration(1<<(len(d.failures)-1)) * time.Second
	d.setStatus("connecting", fmt.Sprintf("%s，%s 后重连", reason, backoff))
	gen := d.gen
	time.AfterFunc(backoff, func() {
		d.ctl.Lock()
		defer d.ctl.Unlock()
		d.mu.Lock()
		stale := d.gen != gen || d.closing || !d.state.Connected || d.conn != nil
		scenario := d.state.Scenario
		d.mu.Unlock()
		if stale {
			return
		}
		if err := d.connectLocked(scenario); err != nil {
			d.retryLocked(err.Error())
		}
	})
}

// reconcile runs on every change notification and every checkInterval
// while the daemon wants to be connected, 6.4: a changed physical DNS
// reloads the engine with it, a lost resolver key is published again, and
// an engine that stops answering is restarted. A connection that gave up
// starts again when the physical network changes.
func (d *Daemon) reconcile() {
	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	c, want, closing, status, last := d.conn, d.state.Connected, d.closing, d.status, d.physical
	scenario := d.state.Scenario
	d.mu.Unlock()
	if closing || !want {
		return
	}
	physical, err := d.sys.PhysicalDNS()
	if err != nil {
		return
	}
	physical = usablePhysical(physical)
	if c == nil {
		if status == "failed" && !sameServers(physical, last) {
			d.events.add("physical_dns_changed", map[string]any{"servers": physical})
			d.failures = nil
			d.gen++
			if err := d.connectLocked(scenario); err != nil {
				d.retryLocked(err.Error())
			}
		}
		return
	}
	if !sameServers(physical, c.physical) {
		d.events.add("physical_dns_changed", map[string]any{"servers": physical})
		d.gen++
		if err := d.connectLocked(c.scenario); err != nil {
			d.retryLocked(err.Error())
		}
		return
	}
	select {
	case <-c.resolver.Done():
		// The session died without the daemon closing it; hold the key
		// again in a new one.
		r, err := d.sys.Hold(d.opts.Layout.DNSKey(), c.lock.file)
		if err != nil {
			d.events.add("dns_hold_failed", map[string]any{"error": err.Error()})
			d.gen++
			d.disconnectLocked()
			d.retryLocked("系统 DNS 会话退出后没能重建")
			return
		}
		d.mu.Lock()
		c.resolver = r
		d.mu.Unlock()
		d.wakeMonitor()
		d.events.add("dns_session_restarted", nil)
	default:
	}
	published, first, err := d.sys.Resolver(d.opts.Layout.DNSKey())
	if err == nil && !published {
		// configd lost it, as when configd restarts.
		_ = c.resolver.Republish()
		d.events.add("dns_republished", nil)
		published, first = d.checkResolver()
	}
	if first != c.first {
		d.events.add("dns_first_changed", map[string]any{"first": first})
	}
	d.mu.Lock()
	c.first = first
	d.mu.Unlock()
	if err := d.sys.Probe(); err != nil {
		c.probeMiss++
		if c.probeMiss >= maxProbeMiss {
			// The engine is alive but not answering: restart it as if it
			// had crashed.
			d.events.add("engine_unresponsive", map[string]any{"pid": c.engine.pid})
			_ = c.engine.cmd.Process.Kill()
		}
		return
	}
	c.probeMiss = 0
}
