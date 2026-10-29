package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sort"
	"time"

	"github.com/kafeifei/xdial-next/internal/buildinfo"
	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
	"github.com/kafeifei/xdial-next/internal/store"
)

// Output schemas of the API methods; the CLI prints them as they come.
const (
	SchemaDaemonVersion = "xdial.daemon.version/v1"
	SchemaStatus        = "xdial.status/v1"
	SchemaConfigExport  = "xdial.config.export/v1"
	SchemaConfigApply   = "xdial.config.apply/v1"
	SchemaSecret        = "xdial.secret/v1"
	SchemaSecretList    = "xdial.secret.list/v1"
)

func (d *Daemon) methods() map[string]func(json.RawMessage) reply {
	return map[string]func(json.RawMessage) reply{
		"version":             d.version,
		"status":              d.statusMethod,
		"config.export":       d.export,
		"config.apply":        d.apply,
		"secret.set":          d.secretSet,
		"secret.list":         d.secretList,
		"secret.rm":           d.secretRemove,
		"connect":             d.connect,
		"disconnect":          d.disconnect,
		"scenario.use":        d.scenarioUse,
		"tailscale.login":     d.tailscaleLogin,
		"tailscale.logout":    d.tailscaleLogout,
		"rule_set.list":       d.ruleSetList,
		"rule_set.update":     d.ruleSetUpdate,
		"subscription.list":   d.subscriptionList,
		"subscription.update": d.subscriptionUpdate,
		"subscription.show":   d.subscriptionShow,
	}
}

func (d *Daemon) version(json.RawMessage) reply {
	return reply{schema: SchemaDaemonVersion, result: map[string]any{
		"version": buildinfo.Version, "revision": buildinfo.Revision(), "build": buildinfo.Build(), "sing_box": buildinfo.SingBox(), "api": 1,
	}}
}

// Status is the result of status and of the methods that change it,
// ARCHITECTURE.md 6.3. State is what is true now; Intent is what the user
// asked for, which the daemon keeps working towards.
type Status struct {
	State       string    `json:"state"`
	Intent      string    `json:"intent"`
	Connected   bool      `json:"connected"`
	Scenario    string    `json:"scenario"`
	Revision    string    `json:"revision"`
	Since       time.Time `json:"since"`
	LastError   string    `json:"last_error"`
	SystemDNS   bool      `json:"system_dns"`
	PhysicalDNS []string  `json:"physical_dns"`
	EnginePID   int       `json:"engine_pid"`
	// Endpoints is what the engine last reported about the AnyConnect and
	// Tailscale lines of the connection, by line id, 6.3.
	Endpoints map[string]engine.EndpointStatus `json:"endpoints,omitempty"`
}

func (d *Daemon) statusLocked() Status {
	s := Status{
		State: d.status, Intent: "disconnected", Connected: d.status == "connected", Scenario: d.state.Scenario,
		Revision: d.revision(), Since: d.since.UTC(), LastError: d.lastErr, PhysicalDNS: []string{},
	}
	if d.state.Connected {
		s.Intent = "connected"
	}
	physical := d.physical
	if d.conn != nil {
		physical = d.conn.physical
	}
	for _, a := range physical {
		s.PhysicalDNS = append(s.PhysicalDNS, a.String())
	}
	if c := d.conn; c != nil {
		s.EnginePID = c.engine.pid
		s.SystemDNS = c.first == resolverAddress.String()
		if endpoints := c.engine.endpointStatus(); len(endpoints) > 0 {
			s.Endpoints = endpoints
		}
	}
	return s
}

func (d *Daemon) currentStatus() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.statusLocked()
}

func (d *Daemon) statusMethod(json.RawMessage) reply {
	return reply{schema: SchemaStatus, result: d.currentStatus()}
}

func (d *Daemon) export(json.RawMessage) reply {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == nil {
		return reply{err: cli.Errorf(cli.CodeConfigInvalid, "先用 xdial config apply 提交配置", "还没有配置")}
	}
	return reply{schema: SchemaConfigExport, result: map[string]any{
		"revision": d.revision(), "content": json.RawMessage(d.cfg.Root.Canonical()),
	}}
}

// Change is one object an apply adds, removes or changes.
type Change struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Change string `json:"change"`
}

// SecretRef is one secret and where the configuration uses it.
type SecretRef struct {
	Name       string   `json:"name"`
	Set        bool     `json:"set"`
	Updated    string   `json:"updated,omitempty"`
	References []string `json:"references"`
}

// ApplyResult is the result of config.apply.
type ApplyResult struct {
	Applied          bool        `json:"applied"`
	Revision         string      `json:"revision"`
	PreviousRevision string      `json:"previous_revision"`
	Changes          []Change    `json:"changes"`
	MissingSecrets   []string    `json:"missing_secrets"`
	Secrets          []SecretRef `json:"secrets"`
	Pending          []string    `json:"pending"`
	Reloaded         bool        `json:"reloaded"`
}

// apply replaces the whole configuration after every check of section 2
// and 3.1 has passed, ARCHITECTURE.md 4.1. Connected, the new
// configuration must start before it is written; otherwise the old one
// keeps running and nothing changes.
func (d *Daemon) apply(params json.RawMessage) reply {
	var p struct {
		Content string `json:"content"`
		DryRun  bool   `json:"dry_run"`
		IfMatch string `json:"if_match"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	c, problems, err := config.Load([]byte(p.Content))
	if errors.Is(err, config.ErrNewerVersion) {
		return reply{err: cli.Errorf(cli.CodeConfigVersion, "", "这份配置的 version 比 daemon 支持的 %d 新", config.CurrentVersion)}
	}
	if err != nil {
		return reply{err: err}
	}
	if len(problems) > 0 {
		return reply{err: &cli.Error{Code: cli.CodeConfigInvalid, Message: fmt.Sprintf("配置有 %d 处问题", len(problems)), Problems: problems}}
	}
	verification, err := engine.Verify(context.Background(), d.opts.Executable, c)
	if err != nil {
		return reply{err: cli.Errorf(cli.CodeInternal, "", "%v", err)}
	}
	if len(verification.Problems) > 0 {
		return reply{err: &cli.Error{Code: cli.CodeConfigInvalid, Message: fmt.Sprintf("配置有 %d 处问题", len(verification.Problems)), Problems: verification.Problems}}
	}

	// Connected, the new configuration's scenario must come up: what it
	// needs is downloaded first, outside the control sequence.
	d.mu.Lock()
	want, scenario := d.state.Connected, d.state.Scenario
	d.mu.Unlock()
	if want && !p.DryRun {
		if err := d.fetchFor(c, scenario); err != nil {
			return reply{err: err}
		}
	}

	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	revision, current, secrets := d.revision(), d.cfg, maps.Clone(d.secrets)
	live, want, scenario := d.conn != nil, d.state.Connected, d.state.Scenario
	d.mu.Unlock()
	if p.IfMatch != "" && p.IfMatch != revision {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "重新 xdial config export 后再改", "配置已经被改过：现在是 %s", revision)}
	}
	scenarioGone := true
	for _, s := range c.Scenarios {
		scenarioGone = scenarioGone && s.ID != scenario
	}
	if want && scenarioGone {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "先 xdial scenario use 切到别的场景", "新配置删掉了正在用的场景 %q", scenario)}
	}
	if err := checkFormats(c, secrets); err != nil {
		return reply{err: err}
	}
	result := ApplyResult{
		Revision: c.Root.Revision(), PreviousRevision: revision,
		Changes: diff(current, c), Secrets: secretRefs(c, secrets), Pending: verification.Pending,
		MissingSecrets: []string{},
	}
	for _, s := range result.Secrets {
		if !s.Set {
			result.MissingSecrets = append(result.MissingSecrets, s.Name)
		}
	}
	if p.DryRun {
		return reply{schema: SchemaConfigApply, result: result}
	}

	// Connected, the new configuration must come up before it is stored,
	// and stored before it is current; if either fails, the old one comes
	// back and nothing changes, 4.1.
	canonical := c.Root.Canonical()
	if live {
		reload, err := d.prepare(c, scenario)
		if err != nil {
			return reply{err: err}
		}
		d.gen++
		if err := d.bringUp(reload); err != nil {
			d.restoreLocked()
			return reply{err: err}
		}
		result.Reloaded = true
	}
	if err := store.WriteFile(d.opts.Layout.Config(), canonical, 0o600); err != nil {
		if live {
			d.gen++
			d.restoreLocked()
		}
		return reply{err: cli.Errorf(cli.CodeInternal, "", "保存配置失败，配置没有变：%v", err)}
	}
	d.mu.Lock()
	d.cfg, d.raw = c, canonical
	d.mu.Unlock()
	result.Applied = true
	d.events.add("config_applied", map[string]any{"revision": result.Revision, "previous": result.PreviousRevision})
	d.wakeResources()
	return reply{schema: SchemaConfigApply, result: result}
}

// restoreLocked brings the stored configuration back up after a reload
// with a new one failed.
func (d *Daemon) restoreLocked() {
	if err := d.establishLocked(); err != nil {
		// Never leave the uncommitted configuration running: take it down
		// and retry the stored one.
		d.disconnectLocked()
		d.retryLocked("新配置没能启动或保存，旧配置也没能恢复：" + err.Error())
	}
}

// diff lists the objects an apply adds, removes or changes, by kind and id.
func diff(old, next *config.Config) []Change {
	type key struct{ kind, id string }
	index := func(c *config.Config) map[key]string {
		m := map[key]string{}
		if c == nil {
			return m
		}
		for _, list := range [][]*config.Object{c.Lines, c.Groups, c.RuleSets, c.Subscriptions} {
			for _, o := range list {
				m[key{o.Kind, o.ID}] = string(o.Value.Canonical())
			}
		}
		for _, s := range c.Scenarios {
			m[key{"scenario", s.ID}] = string(s.Value.Canonical())
		}
		if c.Mixed != nil {
			m[key{"mixed", ""}] = string(c.Mixed.Canonical())
		}
		return m
	}
	before, after := index(old), index(next)
	changes := []Change{}
	for k, v := range after {
		if prev, ok := before[k]; !ok {
			changes = append(changes, Change{k.kind, k.id, "added"})
		} else if prev != v {
			changes = append(changes, Change{k.kind, k.id, "changed"})
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			changes = append(changes, Change{k.kind, k.id, "removed"})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		return changes[i].ID < changes[j].ID
	})
	return changes
}

func secretRefs(c *config.Config, secrets map[string]Secret) []SecretRef {
	refs := map[string][]string{}
	if c != nil {
		for _, use := range c.Secrets {
			refs[use.Name] = append(refs[use.Name], use.Path)
		}
	}
	for name := range secrets {
		if _, ok := refs[name]; !ok {
			refs[name] = []string{}
		}
	}
	names := make([]string, 0, len(refs))
	for name := range refs {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]SecretRef, 0, len(names))
	for _, name := range names {
		r := SecretRef{Name: name, References: refs[name]}
		if s, ok := secrets[name]; ok {
			r.Set, r.Updated = true, s.Updated.UTC().Format(time.RFC3339)
		}
		out = append(out, r)
	}
	return out
}

func (d *Daemon) secretSet(params json.RawMessage) reply {
	var p struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	if !validSecretName(p.Name) {
		return reply{err: cli.Errorf(cli.CodeUsage, "", "凭据名 %q 不合法：只能用小写字母、数字和连字符，以字母或数字开头，最长 63 个字符", p.Name)}
	}
	if p.Value == "" {
		return reply{err: cli.Errorf(cli.CodeSecretFormat, "", "凭据的值不能为空")}
	}
	if len(p.Value) > MaxSecretLength {
		return reply{err: cli.Errorf(cli.CodeSecretFormat, "", "凭据最长 %d 字节", MaxSecretLength)}
	}
	// Secrets are what connections are built from: change them in the
	// control sequence, never in the middle of an apply or a reload.
	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg != nil {
		if err := checkFormats(d.cfg, map[string]Secret{p.Name: {Value: p.Value}}); err != nil {
			return reply{err: err}
		}
	}
	previous, had := d.secrets[p.Name]
	d.secrets[p.Name] = Secret{Value: p.Value, Updated: time.Now()}
	if err := d.saveSecrets(); err != nil {
		if had {
			d.secrets[p.Name] = previous
		} else {
			delete(d.secrets, p.Name)
		}
		return reply{err: err}
	}
	d.events.add("secret_set", map[string]any{"name": p.Name})
	d.wakeResources()
	for _, r := range secretRefs(d.cfg, d.secrets) {
		if r.Name == p.Name {
			return reply{schema: SchemaSecret, result: r}
		}
	}
	return reply{schema: SchemaSecret, result: SecretRef{Name: p.Name, Set: true, References: []string{}}}
}

func (d *Daemon) secretList(json.RawMessage) reply {
	d.mu.Lock()
	defer d.mu.Unlock()
	return reply{schema: SchemaSecretList, result: map[string]any{"secrets": secretRefs(d.cfg, d.secrets)}}
}

func (d *Daemon) secretRemove(params json.RawMessage) reply {
	var p struct {
		Name string `json:"name"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range secretRefs(d.cfg, d.secrets) {
		if r.Name == p.Name && len(r.References) > 0 {
			return reply{err: cli.Errorf(cli.CodeSecretInUse, "先改掉这些引用", "凭据 %s 仍被引用：%v", p.Name, r.References)}
		}
	}
	if _, ok := d.secrets[p.Name]; !ok {
		return reply{err: cli.Errorf(cli.CodeSecretMissing, "", "没有凭据 %s", p.Name)}
	}
	previous := d.secrets[p.Name]
	delete(d.secrets, p.Name)
	if err := d.saveSecrets(); err != nil {
		d.secrets[p.Name] = previous
		return reply{err: err}
	}
	d.events.add("secret_removed", map[string]any{"name": p.Name})
	return reply{schema: SchemaSecret, result: SecretRef{Name: p.Name, References: []string{}}}
}

// connect brings up a scenario, or the last one. Connecting again to the
// connection that is up changes nothing. A connect that fails before
// anything changed leaves everything as it was; one that fails later
// leaves the daemon working towards what the user asked for before, 6.3.
func (d *Daemon) connect(params json.RawMessage) reply {
	var p struct {
		Scenario string `json:"scenario"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	d.mu.Lock()
	cfg, scenario := d.cfg, p.Scenario
	if scenario == "" {
		scenario = d.state.Scenario
	}
	d.mu.Unlock()
	scenario = defaultScenario(cfg, scenario)
	if err := d.fetchFor(cfg, scenario); err != nil {
		return reply{err: err}
	}
	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	cfg, c := d.cfg, d.conn
	d.mu.Unlock()
	next, err := d.prepare(cfg, scenario)
	if err != nil {
		return reply{err: err}
	}
	// Nothing to do only if the engine would run exactly this: a rule set
	// downloaded since, or a new physical DNS, makes it differ.
	if c != nil && c.scenario == next.scenario && c.digest == next.digest {
		return reply{schema: SchemaStatus, result: d.currentStatus()}
	}
	if err := d.switchLocked(next); err != nil {
		return reply{err: err}
	}
	d.events.add("connected", map[string]any{"scenario": next.scenario})
	return reply{schema: SchemaStatus, result: d.currentStatus()}
}

// disconnect stores the user's intent before taking anything down, so a
// daemon killed halfway does not reconnect when it comes back; if storing
// fails, nothing changes. Any retry pending is dropped, 6.3.
func (d *Daemon) disconnect(json.RawMessage) reply {
	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	next := d.state
	d.mu.Unlock()
	next.Connected = false
	if err := d.persist(next); err != nil {
		return reply{err: cli.Errorf(cli.CodeInternal, "", "保存断开状态失败，连接没有动：%v", err)}
	}
	d.gen++
	d.disconnectLocked()
	d.setStatus("disconnected", "")
	d.events.add("disconnected", nil)
	return reply{schema: SchemaStatus, result: d.currentStatus()}
}

// scenarioUse switches the scenario. While the user wants to be connected,
// it is a connect to the new scenario.
func (d *Daemon) scenarioUse(params json.RawMessage) reply {
	var p struct {
		ID string `json:"id"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	d.mu.Lock()
	cfg, want := d.cfg, d.state.Connected
	d.mu.Unlock()
	if want {
		if err := d.fetchFor(cfg, p.ID); err != nil {
			return reply{err: err}
		}
	}
	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	cfg, want = d.cfg, d.state.Connected
	d.mu.Unlock()
	if cfg == nil {
		return reply{err: cli.Errorf(cli.CodeConfigInvalid, "先用 xdial config apply 提交配置", "还没有配置")}
	}
	found := false
	for _, s := range cfg.Scenarios {
		found = found || s.ID == p.ID
	}
	if !found {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "", "场景 %q 不存在", p.ID)}
	}
	if want {
		next, err := d.prepare(cfg, p.ID)
		if err != nil {
			return reply{err: err}
		}
		if err := d.switchLocked(next); err != nil {
			return reply{err: err}
		}
	} else if err := d.persist(State{Scenario: p.ID}); err != nil {
		return reply{err: cli.Errorf(cli.CodeInternal, "", "保存场景失败：%v", err)}
	}
	d.events.add("scenario_used", map[string]any{"scenario": p.ID})
	return reply{schema: SchemaStatus, result: d.currentStatus()}
}

// checkSecrets reports the secrets a compilation needs that are not set,
// and checks the ones that are against the fields that use them, without
// ever echoing a value.
func checkSecrets(c *config.Config, secrets map[string]Secret, used []string) error {
	var missing []string
	for _, name := range used {
		if _, ok := secrets[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return cli.Errorf(cli.CodeSecretMissing, "用 xdial secret set <名字> 设置", "还没设置的凭据：%v", missing)
	}
	return checkFormats(c, secrets)
}

// checkFormats checks each set secret against every field that uses it.
func checkFormats(c *config.Config, secrets map[string]Secret) error {
	var problems []cli.Problem
	for _, use := range c.Secrets {
		s, ok := secrets[use.Name]
		if !ok {
			continue
		}
		// secret.set refuses longer values; this catches ones stored before.
		if len(s.Value) > MaxSecretLength {
			problems = append(problems, cli.Problem{Code: cli.CodeConfigValue, Path: use.Path, Object: use.Object,
				Message: fmt.Sprintf("凭据 %s 超过 %d 字节，用 xdial secret set 重新设置", use.Name, MaxSecretLength)})
			continue
		}
		if use.Spec.Format == nil {
			continue
		}
		if msg := use.Spec.Format(s.Value, use.Parent); msg != "" {
			problems = append(problems, cli.Problem{Code: cli.CodeConfigValue, Path: use.Path, Object: use.Object, Message: "凭据 " + use.Name + " 的格式不对：" + msg})
		}
	}
	if len(problems) > 0 {
		return &cli.Error{Code: cli.CodeSecretFormat, Message: fmt.Sprintf("%d 处凭据格式不对", len(problems)), Problems: problems}
	}
	return nil
}

func validSecretName(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}
