package config

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
)

// CurrentVersion is the configuration format this build reads and writes.
const CurrentVersion = 1

// Built-in lines, ARCHITECTURE.md 1.4. Their ids are reserved.
const (
	Direct = "direct"
	Block  = "block"
)

// Object is one line, group, rule set, scenario or subscription.
type Object struct {
	Kind  string // "line", "group", "rule_set", "scenario" or "subscription"
	ID    string
	Name  string
	Type  string
	Value *Value
	Path  string // lines[0]
}

// Label names the object the way problems do, as "line hk".
func (o *Object) Label() string { return o.Kind + " " + o.ID }

// ScenarioRule binds a rule set to a line.
type ScenarioRule struct {
	RuleSet string
	Line    string
	Invert  bool
	Path    string
}

// Scenario is a checked scenario.
type Scenario struct {
	Object
	Rules []ScenarioRule
	Final string
}

// Config is a checked configuration. It is only returned without problems.
type Config struct {
	Root          *Value
	Version       int
	Mixed         *Value
	Lines         []*Object
	Groups        []*Object
	RuleSets      []*Object
	Scenarios     []*Scenario
	Subscriptions []*Object
	Secrets       []SecretUse
}

// Line returns the line or group with id, or nil.
func (c *Config) Line(id string) *Object {
	for _, o := range c.Lines {
		if o.ID == id {
			return o
		}
	}
	for _, o := range c.Groups {
		if o.ID == id {
			return o
		}
	}
	return nil
}

// RuleSet returns the rule set with id, or nil.
func (c *Config) RuleSet(id string) *Object {
	for _, o := range c.RuleSets {
		if o.ID == id {
			return o
		}
	}
	return nil
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func validID(s string) bool { return idPattern.MatchString(s) }

func sortedStrings(list []string) []string {
	sort.Strings(list)
	return list
}

// ErrNewerVersion means the document was written for a newer XDial.
var ErrNewerVersion = errors.New("configuration version is newer than this build")

// Load parses and checks a configuration document. It returns the checked
// configuration, or every problem found; it never stops at the first one
// unless the document cannot be parsed at all.
func Load(data []byte) (*Config, []cli.Problem, error) {
	root, err := Parse(data)
	if err != nil {
		var dup *DuplicateKeyError
		code := cli.CodeConfigSyntax
		if errors.As(err, &dup) {
			code = cli.CodeConfigDuplicateKey
		}
		return nil, []cli.Problem{{Code: code, Message: err.Error(), Hint: "JSON 里可以写 // 和 /* */ 注释，也可以有尾逗号"}}, nil
	}
	if root.Kind != KindObject {
		return nil, []cli.Problem{{Code: cli.CodeConfigValue, Message: "配置应该是一个 JSON 对象"}}, nil
	}
	if v := root.Get("version"); v != nil {
		if n, ok := integer(v); ok && n > CurrentVersion {
			return nil, nil, ErrNewerVersion
		}
	}

	w := &walker{}
	spec := documentSpec()
	c := &Config{Root: root}
	for _, f := range root.Fields {
		s, ok := spec[f.Key]
		if !ok {
			w.problem(cli.CodeConfigUnknownKey, f.Key, unknownKeyHint(f.Key, spec), "没有登记的键 %q", f.Key)
			continue
		}
		if s.shape != shapeArray || f.Value.Kind != KindArray {
			w.label = ""
			w.field(f.Value, s, f.Key, root)
			continue
		}
		if len(f.Value.Items) > s.maxItems {
			w.problem(cli.CodeConfigValue, f.Key, "", "最多 %d 项，这里有 %d 项", s.maxItems, len(f.Value.Items))
			continue
		}
		for i, item := range f.Value.Items {
			path := fmt.Sprintf("%s[%d]", f.Key, i)
			o := &Object{Kind: kindOf(f.Key), Value: item, Path: path}
			if id := item.Get("id"); id != nil && id.Kind == KindString {
				o.ID = id.String
			}
			if name := item.Get("name"); name != nil && name.Kind == KindString {
				o.Name = name.String
			}
			if typ := item.Get("type"); typ != nil && typ.Kind == KindString {
				o.Type = typ.String
			}
			w.label = o.Label()
			w.field(item, s.elem, path, f.Value)
			c.add(o)
		}
	}
	w.label = ""
	for _, key := range sortedKeys(spec) {
		if spec[key].required && root.Get(key) == nil {
			w.problem(cli.CodeConfigValue, key, "", "缺少必填的 %s", key)
		}
	}
	if v := root.Get("version"); v != nil {
		if n, ok := integer(v); ok {
			c.Version = int(n)
		}
	}
	c.Mixed = root.Get("mixed")
	c.Secrets = w.secrets
	if !w.failed() {
		c.checkObjects(w)
	}
	if w.dropped > 0 {
		w.problems = append(w.problems, cli.Problem{Code: cli.CodeConfigMore, Message: fmt.Sprintf("还有 %d 处问题没有列出", w.dropped), Hint: "先改掉上面这些，再重新检查"})
	}
	if w.failed() {
		return nil, w.problems, nil
	}
	return c, nil, nil
}

func kindOf(key string) string {
	switch key {
	case "lines":
		return "line"
	case "groups":
		return "group"
	case "rule_sets":
		return "rule_set"
	case "scenarios":
		return "scenario"
	default:
		return "subscription"
	}
}

func (c *Config) add(o *Object) {
	switch o.Kind {
	case "line":
		c.Lines = append(c.Lines, o)
	case "group":
		c.Groups = append(c.Groups, o)
	case "rule_set":
		c.RuleSets = append(c.RuleSets, o)
	case "scenario":
		s := &Scenario{Object: *o}
		if final := o.Value.Get("final"); final != nil {
			s.Final = final.String
		}
		if rules := o.Value.Get("rules"); rules != nil {
			for i, r := range rules.Items {
				rule := ScenarioRule{Path: fmt.Sprintf("%s.rules[%d]", o.Path, i)}
				if v := r.Get("rule_set"); v != nil {
					rule.RuleSet = v.String
				}
				if v := r.Get("line"); v != nil {
					rule.Line = v.String
				}
				if v := r.Get("invert"); v != nil {
					rule.Invert = v.Bool
				}
				s.Rules = append(s.Rules, rule)
			}
		}
		c.Scenarios = append(c.Scenarios, s)
	default:
		c.Subscriptions = append(c.Subscriptions, o)
	}
}

// checkObjects runs the checks that need the whole configuration: unique
// ids, references, cycles and the rules sing-box only enforces at start.
func (c *Config) checkObjects(w *walker) {
	problem := func(o *Object, code, path, hint, format string, args ...any) {
		w.problemFor(o.Label(), code, path, hint, format, args...)
	}

	// Lines and groups share a namespace because both are outbounds.
	outbounds := map[string]*Object{}
	for _, list := range [][]*Object{c.Lines, c.Groups} {
		for _, o := range list {
			if o.ID == Direct || o.ID == Block {
				problem(o, cli.CodeConfigDuplicateID, o.Path+".id", "换一个 id", "%s 是内置线路，id 保留", o.ID)
				continue
			}
			if prev, ok := outbounds[o.ID]; ok {
				problem(o, cli.CodeConfigDuplicateID, o.Path+".id", "线路和线路组共用一个命名空间", "id %q 和 %s 重复", o.ID, prev.Path)
				continue
			}
			outbounds[o.ID] = o
		}
	}
	for _, list := range [][]*Object{c.RuleSets, c.Subscriptions} {
		seen := map[string]*Object{}
		for _, o := range list {
			if prev, ok := seen[o.ID]; ok {
				problem(o, cli.CodeConfigDuplicateID, o.Path+".id", "", "id %q 和 %s 重复", o.ID, prev.Path)
				continue
			}
			seen[o.ID] = o
		}
	}
	scenarios := map[string]*Scenario{}
	for _, s := range c.Scenarios {
		if prev, ok := scenarios[s.ID]; ok {
			problem(&s.Object, cli.CodeConfigDuplicateID, s.Path+".id", "", "id %q 和 %s 重复", s.ID, prev.Path)
			continue
		}
		scenarios[s.ID] = s
	}
	ruleSets := map[string]*Object{}
	for _, o := range c.RuleSets {
		ruleSets[o.ID] = o
	}

	// References. Detours, group members and download_via name an outbound;
	// scenario rules and final may also name block.
	outboundRef := func(o *Object, path, id string, allowBlock bool) {
		switch {
		case id == Direct:
		case id == Block && allowBlock:
		case id == Block:
			problem(o, cli.CodeConfigReference, path, "block 只能当场景规则的目标或 final", "这里不能用 block")
		case outbounds[id] == nil:
			problem(o, cli.CodeConfigReference, path, "先在 lines 或 groups 里定义它", "引用的线路 %q 不存在", id)
		}
	}
	for _, o := range append(append([]*Object{}, c.Lines...), c.Groups...) {
		if d := o.Value.Get("detour"); d != nil {
			if d.String == Direct {
				// sing-box refuses every dial through an empty direct
				// detour, but only when traffic arrives.
				problem(o, cli.CodeConfigReference, o.Path+".detour", "去掉 detour，不写就是直连", "detour 不能是 direct")
			} else {
				outboundRef(o, o.Path+".detour", d.String, false)
			}
		}
		if members := o.Value.Get("outbounds"); members != nil {
			ids := map[string]bool{}
			for i, m := range members.Items {
				outboundRef(o, fmt.Sprintf("%s.outbounds[%d]", o.Path, i), m.String, false)
				ids[m.String] = true
			}
			if len(members.Items) == 0 {
				problem(o, cli.CodeConfigValue, o.Path+".outbounds", "", "线路组至少要有一个成员")
			}
			if def := o.Value.Get("default"); def != nil && !ids[def.String] {
				problem(o, cli.CodeConfigReference, o.Path+".default", "default 必须是 outbounds 里的一个", "default %q 不是这个组的成员", def.String)
			}
		}
		if o.Type == "shadowsocks" {
			c.checkPlugin(o, w)
		}
		checkCrossField(o, w)
	}
	for _, o := range append(append([]*Object{}, c.RuleSets...), c.Subscriptions...) {
		if via := o.Value.Get("download_via"); via != nil {
			outboundRef(o, o.Path+".download_via", via.String, false)
		}
	}
	for _, s := range c.Scenarios {
		for _, r := range s.Rules {
			if ruleSets[r.RuleSet] == nil {
				problem(&s.Object, cli.CodeConfigReference, r.Path+".rule_set", "先在 rule_sets 里定义它", "引用的规则集 %q 不存在", r.RuleSet)
			}
			outboundRef(&s.Object, r.Path+".line", r.Line, true)
		}
		outboundRef(&s.Object, s.Path+".final", s.Final, true)
	}
	if w.failed() {
		return
	}

	// Cycles through detours and group members; sing-box only finds them at
	// start, which sing-box check never reaches.
	state := map[string]int{}
	var visit func(id string, trail []string) bool
	visit = func(id string, trail []string) bool {
		o := outbounds[id]
		if o == nil {
			return false
		}
		switch state[id] {
		case 1:
			cycle := append(trail[indexOf(trail, id):], id)
			problem(o, cli.CodeConfigCycle, o.Path, "去掉其中一处 detour 或组成员", "成环：%s", strings.Join(cycle, " → "))
			return true
		case 2:
			return false
		}
		state[id] = 1
		for _, next := range outboundEdges(o) {
			if visit(next, append(trail, id)) {
				return true
			}
		}
		state[id] = 2
		return false
	}
	for _, list := range [][]*Object{c.Lines, c.Groups} {
		for _, o := range list {
			if visit(o.ID, nil) {
				return
			}
		}
	}

	// A download runs in a one-shot instance holding only the line chain it
	// names, so that chain must not reach an endpoint, ARCHITECTURE.md 3.4.
	for _, o := range append(append([]*Object{}, c.RuleSets...), c.Subscriptions...) {
		via := o.Value.Get("download_via")
		if via == nil {
			continue
		}
		if endpoint := c.reachesEndpoint(via.String, map[string]bool{}); endpoint != "" {
			problem(o, cli.CodeConfigReference, o.Path+".download_via", "换一条代理线路或 direct", "下载线路会经过 endpoint 线路 %q，下载时它还没上线", endpoint)
		}
		// direct named as download_via is checked against local and internal
		// addresses; direct reached through a group would dial with sing-box's
		// own direct outbound, which checks nothing.
		if via.String != Direct && c.reachesDirect(via.String, map[string]bool{}) {
			problem(o, cli.CodeConfigReference, o.Path+".download_via", "直连下载写 direct；经组下载时组里不要有 direct", "下载线路 %q 经组会走到 direct，绕过对本机和内网地址的检查", via.String)
		}
	}
}

func (c *Config) reachesDirect(id string, seen map[string]bool) bool {
	if id == Direct {
		return true
	}
	if seen[id] {
		return false
	}
	seen[id] = true
	o := c.Line(id)
	if o == nil {
		return false
	}
	for _, next := range outboundEdges(o) {
		if c.reachesDirect(next, seen) {
			return true
		}
	}
	return false
}

func outboundEdges(o *Object) []string {
	var edges []string
	if d := o.Value.Get("detour"); d != nil {
		edges = append(edges, d.String)
	}
	if members := o.Value.Get("outbounds"); members != nil {
		for _, m := range members.Items {
			edges = append(edges, m.String)
		}
	}
	return edges
}

func (c *Config) reachesEndpoint(id string, seen map[string]bool) string {
	if seen[id] {
		return ""
	}
	seen[id] = true
	o := c.Line(id)
	if o == nil {
		return ""
	}
	if endpointTypes[o.Type] {
		return o.ID
	}
	for _, next := range outboundEdges(o) {
		if found := c.reachesEndpoint(next, seen); found != "" {
			return found
		}
	}
	return ""
}

func (c *Config) checkPlugin(o *Object, w *walker) {
	opts := o.Value.Get("plugin_opts")
	if opts == nil {
		return
	}
	if o.Value.Get("plugin") == nil {
		w.problemFor(o.Label(), cli.CodeConfigValue, o.Path+".plugin_opts", "", "写了 plugin_opts 却没写 plugin")
		return
	}
	if msg := pluginOptions(o.Value)(opts); msg != "" {
		w.problemFor(o.Label(), cli.CodeConfigValue, o.Path+".plugin_opts", "", "%s", msg)
	}
}

// Defaults sing-box fills in, which cross-field checks compare against.
const (
	defaultURLTestInterval    = 3 * time.Minute
	defaultURLTestIdleTimeout = 30 * time.Minute
)

// checkCrossField checks constraints between fields of one object that
// sing-box only rejects when starting, or not at all, ARCHITECTURE.md 2.4.
func checkCrossField(o *Object, w *walker) {
	problem := func(path, format string, args ...any) {
		w.problemFor(o.Label(), cli.CodeConfigValue, path, "", format, args...)
	}
	if o.Type == "urltest" {
		interval := durationOr(o.Value.Get("interval"), defaultURLTestInterval)
		idle := durationOr(o.Value.Get("idle_timeout"), defaultURLTestIdleTimeout)
		if interval > idle {
			problem(o.Path+".interval", "interval（%s）不能大于 idle_timeout（%s）", interval, idle)
		}
	}
	if tls := o.Value.Get("tls"); tls != nil {
		lo, hi := tls.Get("min_version"), tls.Get("max_version")
		if lo != nil && hi != nil && lo.String > hi.String {
			problem(o.Path+".tls.min_version", "min_version %s 高于 max_version %s，没有可用的 TLS 版本", lo.String, hi.String)
		}
		if reality := tls.Get("reality"); reality != nil && isTrue(reality.Get("enabled")) {
			if utls := tls.Get("utls"); utls == nil || !isTrue(utls.Get("enabled")) {
				problem(o.Path+".tls.utls", "reality 需要同时开启 utls")
			}
		}
	}
}

func durationOr(v *Value, fallback time.Duration) time.Duration {
	if v == nil {
		return fallback
	}
	d, err := time.ParseDuration(v.String)
	if err != nil {
		return fallback
	}
	return d
}

func isTrue(v *Value) bool { return v != nil && v.Kind == KindBool && v.Bool }

func indexOf(list []string, s string) int {
	for i, item := range list {
		if item == s {
			return i
		}
	}
	return 0
}
