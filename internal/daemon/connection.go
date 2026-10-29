package daemon

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
)

// Connection control, ARCHITECTURE.md 6.3. Every step that starts, stops or
// replaces the connection, or changes what it is built from, runs under
// d.ctl, one at a time: user requests, reloads, retries after a crash and
// the periodic checks. A retry carries the generation it was scheduled in
// and is dropped if a user request changed the connection since.
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
	digest    [32]byte
	endpoints []string
	physical  []netip.Addr
	lock      *connectionLock
	engine    *engineProc
	resolver  Resolver
	first     string // the system's first resolver, last checked
	probeMiss int
}

// plan is a connection ready to come up: compiled and checked, with
// nothing changed yet.
type plan struct {
	scenario  string
	revision  string
	physical  []netip.Addr
	compiled  []byte
	digest    [32]byte // of compiled: what the engine would run
	endpoints []string // AnyConnect and Tailscale lines compiled in
	secrets   map[string]Secret
}

// defaultScenario is scenario, or the first one of cfg when none is named.
func defaultScenario(cfg *config.Config, scenario string) string {
	if scenario == "" && cfg != nil && len(cfg.Scenarios) > 0 {
		return cfg.Scenarios[0].ID
	}
	return scenario
}

// resumeAfterFetch tries to connect again when the user wants a connection
// that is down for now, typically because retries stopped while what the
// scenario needs was still downloading. A download that completes calls
// it: retries alone stop after 15 seconds, downloads can take longer.
func (d *Daemon) resumeAfterFetch() {
	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	// Only a connection that is down for want of the cache: one that
	// failed for any other reason keeps its stopped retries.
	waiting := d.state.Connected && !d.closing && d.conn == nil && d.status == "failed" && d.awaitingCache
	d.mu.Unlock()
	if !waiting {
		return
	}
	// Only when the cache now holds everything: a download for another
	// scenario must not lift the stopped retries.
	d.mu.Lock()
	cfg, scenario := d.cfg, d.state.Scenario
	d.mu.Unlock()
	scenario = defaultScenario(cfg, scenario)
	if !d.cacheComplete(cfg, scenario) {
		return
	}
	p, err := d.prepare(cfg, scenario)
	// The cache is complete: retries start over, through the usual
	// backoff should anything else, such as reading the physical DNS,
	// fail for a moment.
	d.failures = nil
	d.gen++
	d.mu.Lock()
	d.awaitingCache = false
	d.mu.Unlock()
	if err == nil {
		err = d.bringUp(p)
	} else {
		d.setStatus("failed", err.Error())
	}
	if err != nil {
		d.retryLocked(err.Error())
	}
}

// prepare compiles scenario of cfg with the real secrets and the physical
// DNS and checks everything that can be checked without touching the
// running connection. A request that fails here changes nothing.
func (d *Daemon) prepare(cfg *config.Config, scenario string) (*plan, error) {
	return d.prepareLogin(cfg, scenario, nil)
}

// prepareLogin is prepare with tailscale auth keys for some lines, by id,
// for xdial tailscale login: they are compiled into this one configuration
// only, and scrubbed from what the engine writes like secrets, 4.7.
func (d *Daemon) prepareLogin(cfg *config.Config, scenario string, authKeys map[string]string) (*plan, error) {
	if cfg == nil {
		return nil, cli.Errorf(cli.CodeConfigInvalid, "先用 xdial config apply 提交配置", "还没有配置")
	}
	scenario = defaultScenario(cfg, scenario)
	found := false
	for _, s := range cfg.Scenarios {
		found = found || s.ID == scenario
	}
	if !found {
		return nil, cli.Errorf(cli.CodeConfigConflict, "用 xdial scenario use <id> 选一个存在的场景", "场景 %q 不存在", scenario)
	}
	d.mu.Lock()
	secrets := maps.Clone(d.secrets)
	selections := maps.Clone(d.state.Selections)
	scrubbed := maps.Clone(secrets)
	for line, key := range authKeys {
		scrubbed["tailscale-auth-key:"+line] = Secret{Value: key}
	}
	d.mu.Unlock()
	physical, err := d.sys.PhysicalDNS()
	if err != nil {
		return nil, cli.Errorf(cli.CodeEngineFailed, "", "读不到物理网络的 DNS：%v", err)
	}
	physical = usablePhysical(physical)
	d.mu.Lock()
	d.physical = physical
	d.mu.Unlock()
	if len(physical) == 0 {
		return nil, cli.Errorf(cli.CodeEngineFailed, "连上网络后再试；已经连着时，网络就绪后会自动重连", "物理网络还没有 DNS 服务器")
	}
	ruleSets, err := d.cachedRuleSets(cfg, scenario, secrets)
	if err != nil {
		return nil, err
	}
	// Subscriptions the scenario reaches come from the cache only; fetchFor
	// has downloaded what was missing, outside the control sequence, 1.5.
	source := &subscriptionSource{d: d, cfg: cfg, secrets: secrets, content: map[string]*engine.Subscription{}}
	opts := engine.Options{
		Scenario: scenario, TUN: !d.opts.NoTUN, Stack: engine.DefaultStack, StateDirectory: d.opts.Layout.Tailscale(),
		TailscaleAuthKeys: authKeys, Selections: selections,
		PhysicalDNS: physical[0],
		Secret:      func(u config.SecretUse) string { return secrets[u.Name].Value },
		RuleSet: func(o *config.Object) ([]*config.Value, bool) {
			rules, ok := ruleSets[o.ID]
			return rules, ok
		},
		Subscription: source.get,
	}
	result, err := engine.Compile(cfg, opts)
	if err == nil && source.err != nil {
		return nil, source.err
	}
	if err != nil {
		return nil, cli.Errorf(cli.CodeInternal, "", "编译失败：%v", err)
	}
	// Placeholders are for checks only: a rule set that never matches would
	// quietly send its traffic elsewhere, 3.4.
	if len(result.MissingRuleSets) > 0 {
		return nil, cli.Errorf(cli.CodeResourceMissing, "", "场景 %s 用到的远程规则集还没下载：%v", scenario, result.MissingRuleSets)
	}
	if len(result.MissingSubscriptions) > 0 {
		d.wakeResources()
		return nil, cli.Errorf(cli.CodeResourceMissing, "用 xdial subscription update 下载", "场景 %s 用到的订阅还没下载：%v", scenario, result.MissingSubscriptions)
	}
	if result.TooManyMembers {
		return nil, cli.Errorf(cli.CodeResourceTooLarge, "用 filter 少选一些节点，或者少引用几次订阅", "线路组展开后的成员合计超过 %d 个", engine.MaxExpandedMembers)
	}
	if len(result.EmptyGroups) > 0 {
		return nil, cli.Errorf(cli.CodeResourceMissing, "改一下组里订阅成员的 filter 或 exclude，用 xdial subscription show 看节点名", "线路组 %v 从订阅里筛不出任何节点", result.EmptyGroups)
	}
	// Downloaded content joined the configuration only now: check the
	// whole of it before anything running is replaced. The check sees
	// placeholders for secrets, as every check does, 4.5.
	if len(result.JSON) > engine.MaxConfigSize {
		return nil, cli.Errorf(cli.CodeResourceTooLarge, "少用几个大的远程规则集", "场景 %s 编译出的配置超过 %d 字节", scenario, engine.MaxConfigSize)
	}
	placeholders := opts
	placeholders.Secret = engine.Placeholder
	checked, err := engine.Compile(cfg, placeholders)
	if err != nil {
		return nil, cli.Errorf(cli.CodeInternal, "", "编译失败：%v", err)
	}
	if err := engine.Check(context.Background(), d.opts.Executable, checked.JSON); err != nil {
		if errors.Is(err, engine.ErrCheckUnavailable) {
			return nil, cli.Errorf(cli.CodeInternal, "", "%v", err)
		}
		return nil, cli.Errorf(cli.CodeEngineFailed, "", "场景 %s 的配置 sing-box 不接受：%s", scenario, truncate(err.Error(), 300))
	}
	if err := checkSecrets(cfg, secrets, result.Secrets); err != nil {
		return nil, err
	}
	return &plan{scenario: scenario, revision: cfg.Root.Revision(), physical: physical, compiled: result.JSON, digest: sha256.Sum256(result.JSON), endpoints: result.Endpoints, secrets: scrubbed}, nil
}

// bringUp replaces the connection with p, 6.3: take the connection lock,
// start the engine, check through TUN that queries reach sing-box, and only
// then publish the resolver key. Between the old connection going and the
// new one coming up, traffic goes direct. It does not change what the user
// asked for. Callers hold d.ctl.
func (d *Daemon) bringUp(p *plan) error {
	d.mu.Lock()
	old := d.conn
	d.conn = nil
	d.mu.Unlock()
	c := &connection{scenario: p.scenario, revision: p.revision, digest: p.digest, endpoints: p.endpoints, physical: p.physical}
	if old != nil {
		// A reload keeps the lock it holds rather than letting it go and
		// taking it again.
		d.teardown(old, true)
		c.lock = old.lock
	}
	d.setStatus("connecting", "")
	var err error
	if c.lock == nil {
		// Busy means the other identity is connected, or, right after a
		// restart, this daemon's previous engine is still exiting; retries
		// cover the latter.
		c.lock, err = acquireConnectionLock(d.opts.Layout.SharedDir(), d.opts.Layout.ConnectionLock())
		if err != nil {
			d.setStatus("failed", err.Error())
			return err
		}
	}
	c.engine, err = d.startEngine(p.compiled, c.lock.file, newScrubber(p.secrets))
	if err != nil {
		c.lock.release()
		d.events.add("engine_failed", map[string]any{"scenario": p.scenario})
		return d.fail(err.Error())
	}
	d.events.add("engine_started", map[string]any{"scenario": p.scenario, "pid": c.engine.pid})
	if err := d.probe(); err != nil {
		d.teardown(c, false)
		return d.fail("查询进不了 sing-box：" + err.Error())
	}
	c.resolver, err = d.sys.Hold(d.opts.Layout.DNSKey(), c.lock.file)
	if err != nil {
		d.teardown(c, false)
		return d.fail("设置系统 DNS 失败：" + err.Error())
	}
	published, first := d.checkResolver()
	if !published {
		d.teardown(c, false)
		return d.fail("系统 DNS 设置后没有生效")
	}
	c.first = first
	d.events.add("dns_set", map[string]any{"first": first, "physical": p.physical})
	if err := d.sys.FlushCache(); err != nil {
		d.events.add("dns_flush_failed", map[string]any{"error": err.Error()})
	}
	d.mu.Lock()
	d.conn = c
	d.mu.Unlock()
	d.wakeMonitor()
	d.setStatus("connected", notFirst(first))
	go d.watch(c.engine)
	return nil
}

// establishLocked brings up what the user asked for with the stored
// configuration: for resuming, retries and reloads.
func (d *Daemon) establishLocked() error {
	d.mu.Lock()
	cfg, scenario := d.cfg, d.state.Scenario
	d.mu.Unlock()
	p, err := d.prepare(cfg, scenario)
	d.mu.Lock()
	d.awaitingCache = cli.Is(err, cli.CodeResourceMissing)
	d.mu.Unlock()
	if err != nil {
		// Content missing from the cache is downloaded in the background,
		// outside the control sequence; a download that brings it in
		// tries again, resumeAfterFetch.
		d.setStatus("failed", err.Error())
		return err
	}
	return d.bringUp(p)
}

// switchLocked brings up p for a user request and stores it as what the
// user asks for; storing is the commit point. If either fails, the request
// fails, and what the user asked for before is worked towards again.
func (d *Daemon) switchLocked(p *plan) error {
	d.gen++
	d.failures = nil
	if err := d.bringUp(p); err != nil {
		d.resumeIntentLocked(err.Error())
		return err
	}
	if err := d.persist(State{Scenario: p.scenario, Connected: true, Selections: d.selections()}); err != nil {
		d.disconnectLocked()
		d.resumeIntentLocked("保存连接状态失败：" + err.Error())
		return cli.Errorf(cli.CodeInternal, "", "保存连接状态失败，已断开：%v", err)
	}
	return nil
}

// resumeIntentLocked leaves a failed request in a definite state: retrying
// towards a connection the user still wants, or failed.
func (d *Daemon) resumeIntentLocked(reason string) {
	d.mu.Lock()
	want := d.state.Connected
	d.mu.Unlock()
	if want {
		d.retryLocked(reason)
		return
	}
	d.setStatus("failed", reason)
}

// notFirst explains a connection whose resolver key is published but not
// first, as when another VPN's resolver also matches every domain: system
// queries may not reach sing-box, 6.4.
func notFirst(first string) string {
	if first == resolverAddress.String() {
		return ""
	}
	return fmt.Sprintf("系统的第一解析器是 %s，不是 XDial 的，系统查询可能不经过 sing-box", first)
}

func (d *Daemon) wakeMonitor() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// fail records why a connection attempt failed.
func (d *Daemon) fail(reason string) error {
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
		d.teardown(c, false)
	}
}

// teardown stops c; keepLock leaves the lock held for the connection that
// replaces it.
func (d *Daemon) teardown(c *connection, keepLock bool) {
	if c.resolver != nil {
		c.resolver.Close()
		d.events.add("dns_cleared", nil)
	}
	if c.engine != nil {
		c.engine.stop()
		d.events.add("engine_stopped", map[string]any{"pid": c.engine.pid})
	}
	if !keepLock {
		c.lock.release()
	}
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
		d.mu.Unlock()
		if stale {
			return
		}
		if err := d.establishLocked(); err != nil {
			d.retryLocked(err.Error())
		}
	})
}

// reconcile runs on every change notification and every checkInterval
// while the user wants to be connected, 6.4: a changed physical DNS reloads
// the engine with it, a lost resolver key is published again, and an engine
// that stops answering is restarted. A connection that gave up starts again
// when the physical network changes.
func (d *Daemon) reconcile() {
	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	c, want, closing, status, last := d.conn, d.state.Connected, d.closing, d.status, d.physical
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
			if err := d.establishLocked(); err != nil {
				d.retryLocked(err.Error())
			}
		}
		return
	}
	if len(physical) > 0 && physical[0] != c.physical[0] {
		// Only the first server is compiled in, 3.3. While the network
		// changes the key can be gone for a moment: an empty reading, or
		// one that cannot be prepared, keeps the connection as it is.
		d.mu.Lock()
		cfg := d.cfg
		d.mu.Unlock()
		next, err := d.prepare(cfg, c.scenario)
		if err != nil {
			d.events.add("reload_skipped", map[string]any{"error": err.Error()})
			return
		}
		d.events.add("physical_dns_changed", map[string]any{"servers": physical})
		d.gen++
		if err := d.bringUp(next); err != nil {
			d.retryLocked(err.Error())
		}
		return
	}
	select {
	case <-c.resolver.Done():
		// The session died without the daemon closing it; hold the key
		// again in a new one.
		c.resolver.Close()
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
		// configd lost it, as when configd restarts. If adding it again in
		// the same session does not take, start a new session.
		_ = c.resolver.Republish()
		d.events.add("dns_republished", nil)
		if published, first = d.checkResolver(); !published {
			c.resolver.Close()
			r, err := d.sys.Hold(d.opts.Layout.DNSKey(), c.lock.file)
			if err != nil {
				d.gen++
				d.disconnectLocked()
				d.retryLocked("系统 DNS 补写后仍没生效，会话也没能重建")
				return
			}
			d.mu.Lock()
			c.resolver = r
			d.mu.Unlock()
			d.wakeMonitor()
			_, first = d.checkResolver()
		}
	}
	if first != c.first {
		d.events.add("dns_first_changed", map[string]any{"first": first})
		d.setStatus("connected", notFirst(first))
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
