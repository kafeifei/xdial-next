package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		"version":       d.version,
		"status":        d.statusMethod,
		"config.export": d.export,
		"config.apply":  d.apply,
		"secret.set":    d.secretSet,
		"secret.list":   d.secretList,
		"secret.rm":     d.secretRemove,
		"connect":       d.connect,
		"disconnect":    d.disconnect,
		"scenario.use":  d.scenarioUse,
	}
}

func (d *Daemon) version(json.RawMessage) reply {
	return reply{schema: SchemaDaemonVersion, result: map[string]any{
		"version": buildinfo.Version, "revision": buildinfo.Revision(), "sing_box": buildinfo.SingBox(), "api": 1,
	}}
}

// Status is the result of status and of the methods that change it.
type Status struct {
	State     string    `json:"state"`
	Connected bool      `json:"connected"`
	Scenario  string    `json:"scenario"`
	Revision  string    `json:"revision"`
	Since     time.Time `json:"since"`
	LastError string    `json:"last_error"`
	SystemDNS bool      `json:"system_dns"`
	EnginePID int       `json:"engine_pid"`
}

func (d *Daemon) statusLocked() Status {
	s := Status{
		State: d.status, Connected: d.status == "connected", Scenario: d.state.Scenario,
		Revision: d.revision(), Since: d.since.UTC(), LastError: d.lastErr, SystemDNS: d.dnsSet,
	}
	if d.engine != nil {
		s.EnginePID = d.engine.pid
	}
	return s
}

func (d *Daemon) statusMethod(json.RawMessage) reply {
	d.mu.Lock()
	defer d.mu.Unlock()
	return reply{schema: SchemaStatus, result: d.statusLocked()}
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

	d.mu.Lock()
	defer d.mu.Unlock()
	if p.IfMatch != "" && p.IfMatch != d.revision() {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "重新 xdial config export 后再改", "配置已经被改过：现在是 %s", d.revision())}
	}
	connected := d.state.Connected && d.status == "connected"
	scenarioGone := true
	for _, s := range c.Scenarios {
		scenarioGone = scenarioGone && s.ID != d.state.Scenario
	}
	if connected && scenarioGone {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "先 xdial scenario use 切到别的场景", "新配置删掉了正在用的场景 %q", d.state.Scenario)}
	}
	if err := d.checkFormats(c, func(name string) (string, bool) {
		s, ok := d.secrets[name]
		return s.Value, ok
	}); err != nil {
		return reply{err: err}
	}
	result := ApplyResult{
		Revision: c.Root.Revision(), PreviousRevision: d.revision(),
		Changes: diff(d.cfg, c), Secrets: d.secretRefs(c), Pending: verification.Pending,
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

	previous, previousRaw := d.cfg, d.raw
	d.cfg, d.raw = c, c.Root.Canonical()
	if connected {
		if err := d.connectLocked(d.state.Scenario); err != nil {
			d.cfg, d.raw = previous, previousRaw
			if restoreErr := d.connectLocked(d.state.Scenario); restoreErr != nil {
				d.lastErr = "新配置没能启动，旧配置也没能恢复：" + restoreErr.Error()
			}
			return reply{err: err}
		}
		result.Reloaded = true
	}
	if err := store.WriteFile(d.opts.Layout.Config(), d.raw, 0o600); err != nil {
		return reply{err: err}
	}
	result.Applied = true
	d.events.add("config_applied", map[string]any{"revision": result.Revision, "previous": result.PreviousRevision})
	return reply{schema: SchemaConfigApply, result: result}
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

func (d *Daemon) secretRefs(c *config.Config) []SecretRef {
	refs := map[string][]string{}
	if c != nil {
		for _, use := range c.Secrets {
			refs[use.Name] = append(refs[use.Name], use.Path)
		}
	}
	for name := range d.secrets {
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
		if s, ok := d.secrets[name]; ok {
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
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg != nil {
		if err := d.checkFormats(d.cfg, func(name string) (string, bool) {
			if name == p.Name {
				return p.Value, true
			}
			return "", false
		}); err != nil {
			return reply{err: err}
		}
	}
	d.secrets[p.Name] = Secret{Value: p.Value, Updated: time.Now()}
	if err := d.saveSecrets(); err != nil {
		return reply{err: err}
	}
	d.events.add("secret_set", map[string]any{"name": p.Name})
	for _, r := range d.secretRefs(d.cfg) {
		if r.Name == p.Name {
			return reply{schema: SchemaSecret, result: r}
		}
	}
	return reply{schema: SchemaSecret, result: SecretRef{Name: p.Name, Set: true, References: []string{}}}
}

func (d *Daemon) secretList(json.RawMessage) reply {
	d.mu.Lock()
	defer d.mu.Unlock()
	return reply{schema: SchemaSecretList, result: map[string]any{"secrets": d.secretRefs(d.cfg)}}
}

func (d *Daemon) secretRemove(params json.RawMessage) reply {
	var p struct {
		Name string `json:"name"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.secretRefs(d.cfg) {
		if r.Name == p.Name && len(r.References) > 0 {
			return reply{err: cli.Errorf(cli.CodeSecretInUse, "先改掉这些引用", "凭据 %s 仍被引用：%v", p.Name, r.References)}
		}
	}
	if _, ok := d.secrets[p.Name]; !ok {
		return reply{err: cli.Errorf(cli.CodeSecretMissing, "", "没有凭据 %s", p.Name)}
	}
	delete(d.secrets, p.Name)
	if err := d.saveSecrets(); err != nil {
		return reply{err: err}
	}
	d.events.add("secret_removed", map[string]any{"name": p.Name})
	return reply{schema: SchemaSecret, result: SecretRef{Name: p.Name, References: []string{}}}
}

func (d *Daemon) connect(params json.RawMessage) reply {
	var p struct {
		Scenario string `json:"scenario"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	scenario := p.Scenario
	if scenario == "" {
		scenario = d.state.Scenario
	}
	if err := d.connectLocked(scenario); err != nil {
		return reply{err: err}
	}
	d.failures = nil
	return reply{schema: SchemaStatus, result: d.statusLocked()}
}

func (d *Daemon) disconnect(json.RawMessage) reply {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.teardownLocked()
	d.state.Connected = false
	if err := d.saveState(); err != nil {
		return reply{err: err}
	}
	d.setStatus("disconnected", "")
	d.events.add("disconnected", nil)
	return reply{schema: SchemaStatus, result: d.statusLocked()}
}

func (d *Daemon) scenarioUse(params json.RawMessage) reply {
	var p struct {
		ID string `json:"id"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == nil {
		return reply{err: cli.Errorf(cli.CodeConfigInvalid, "先用 xdial config apply 提交配置", "还没有配置")}
	}
	found := false
	for _, s := range d.cfg.Scenarios {
		found = found || s.ID == p.ID
	}
	if !found {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "", "场景 %q 不存在", p.ID)}
	}
	if d.state.Connected && d.status == "connected" {
		if err := d.connectLocked(p.ID); err != nil {
			return reply{err: err}
		}
	} else {
		d.state.Scenario = p.ID
		if err := d.saveState(); err != nil {
			return reply{err: err}
		}
	}
	d.events.add("scenario_used", map[string]any{"scenario": p.ID})
	return reply{schema: SchemaStatus, result: d.statusLocked()}
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
