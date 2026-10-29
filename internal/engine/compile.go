// Package engine turns a checked configuration into the sing-box
// configuration XDial runs, following ARCHITECTURE.md section 3, and checks
// it with sing-box itself through a restricted registry (section 2.3).
package engine

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/kafeifei/xdial-next/internal/config"
)

// Tags XDial generates carry a prefix outside the id character set, so they
// can never collide with a line, group or rule set id, ARCHITECTURE.md 1.4.
const (
	tagPrefix    = "xdial:"
	tagDNSLocal  = tagPrefix + "dns-local"
	tagMixed     = tagPrefix + "mixed"
	tagTUN       = tagPrefix + "tun"
	dnsViaPrefix = tagPrefix + "dns-via-"
	dnsEndpoint  = tagPrefix + "dns-endpoint-"
	dnsRuleSet   = tagPrefix + "dns-rules-"
)

// DoH upstream for proxy lines, ARCHITECTURE.md 3.3.
const proxyDNSServer = "1.1.1.1"

// DefaultStack is the TUN stack, ARCHITECTURE.md 6.3: upstream's default;
// the test VM measured every stack working.
const DefaultStack = "mixed"

// Names sing-box answers NXDOMAIN itself, ARCHITECTURE.md 6.4: where a
// system discovers an encrypted upgrade of its resolver (DDR), and the
// canary that turns off Firefox's own DNS over HTTPS. Either would take DNS
// past sing-box. The daemon also asks the first to check the path into
// sing-box.
var localNXDOMAIN = []string{"_dns.resolver.arpa", "use-application-dns.net"}

// checkPhysicalDNS stands in for the physical network's DNS when checking:
// an address that is never dialled, from TEST-NET-1.
var checkPhysicalDNS = netip.MustParseAddr("192.0.2.53")

// placeholderRule stands in for a remote rule set whose content is not at
// hand: it can never match, ARCHITECTURE.md 4.1.
const placeholderDomain = "placeholder.xdial.invalid"

// Options says what to compile.
type Options struct {
	// Scenario is the scenario to compile. Empty compiles every object with
	// no scenario routing, the whole-configuration check of 3.1.
	Scenario string
	// Secret returns the value of a secret reference. Checks pass
	// Placeholder so the real value never reaches them.
	Secret func(config.SecretUse) string
	// RuleSet returns the downloaded rules of a remote rule set, or false
	// when they are not at hand and a never-matching placeholder is used.
	RuleSet func(*config.Object) ([]*config.Value, bool)
	// StateDirectory holds the tailscale state of each line, by id.
	StateDirectory string
	// Selections are the members picked by hand in selector groups, by
	// group id: compiled as the group's default when still a member, 3.6.
	Selections map[string]string
	// TailscaleAuthKeys logs tailscale lines in with an auth key, by line
	// id: given once by xdial tailscale login, never stored, 4.7.
	TailscaleAuthKeys map[string]string
	// TUN adds the TUN inbound, with Stack as its implementation.
	TUN   bool
	Stack string
	// Subscription returns the downloaded nodes and rules of a
	// subscription, or false when they are not at hand: checks then
	// compile a placeholder node and no rules, 1.5.
	Subscription func(*config.Object) (*Subscription, bool)
	// LogLevel is the sing-box log level XDial sets explicitly, 4.3.
	LogLevel string
	// PhysicalDNS is the physical network's DNS server, read before the
	// system resolver points into TUN, 3.3. direct and the lines' own
	// server names are resolved there, dialled on the physical interface.
	// Unset, as in checks, a placeholder is compiled.
	PhysicalDNS netip.Addr
}

// Placeholder is the Secret function for checks.
func Placeholder(use config.SecretUse) string {
	if use.Spec.Placeholder != nil {
		return use.Spec.Placeholder(use.Parent)
	}
	return "xdial-placeholder"
}

// Result is a compiled configuration.
type Result struct {
	JSON []byte
	// Pending lists what could not be checked, such as remote rule sets
	// compiled with a placeholder, ARCHITECTURE.md 4.2.
	Pending []string
	// MissingRuleSets are the remote rule sets compiled with a placeholder.
	// A placeholder is for checks only; connecting refuses it.
	MissingRuleSets []string
	// MissingSubscriptions are the subscriptions compiled with a
	// placeholder, refused for connecting likewise.
	MissingSubscriptions []string
	// EmptyGroups are groups none of whose members exist: every member
	// came from subscriptions whose nodes the filters left out.
	EmptyGroups []string
	// Endpoints are the AnyConnect and Tailscale lines compiled in, by id.
	Endpoints []string
	// TooManyMembers is set when groups expand to more than
	// MaxExpandedMembers members; the configuration is then not complete.
	TooManyMembers bool
	// Secrets names the secrets the compiled objects use, sorted.
	Secrets []string
	// Groups are the members each compiled group runs with, by id.
	Groups map[string][]string
	// Outbounds are the tags of every line, group and node compiled in.
	Outbounds []string
	// StaleSelections are the groups whose member picked by hand is no
	// longer one of theirs, or that are no longer selectors, 3.6.
	StaleSelections []string
}

type compiler struct {
	c        *config.Config
	opts     Options
	replace  map[*config.Value]string
	pending  []string
	missing  []string
	lines    map[string]bool // outbounds to compile
	ruleSets map[string]bool
	// Subscriptions: content by id, the ones missing, and the nodes the
	// compiled groups use, in order.
	subs        map[string]*Subscription
	missingSubs []string
	nodes       []any
	nodeSeen    map[string]bool
	empty       []string
	members     int
	tooMany     bool
	// bindings are the scenario's rules as compiled: a rule set tag and
	// the line it goes to, in order. generated holds the inline rule sets
	// made from subscription rules.
	bindings  []binding
	generated []generatedSet
}

type binding struct {
	tag    string
	line   string
	invert bool
	// Where it comes from, for explain: the scenario rule's index, and a
	// rule set id or, for subscription rules, the subscription id and the
	// generated set.
	index        int
	ruleSet      string
	subscription string
	generated    int
}

type generatedSet struct {
	tag      string
	rules    []*config.Value
	policies []string // each rule's policy
	within   []int    // each rule's index among the subscription's rules
}

// Subscription is the checked content of one subscription, 1.5.
type Subscription struct {
	Nodes []SubscriptionNode
	Rules []SubscriptionRule
}

// SubscriptionNode is one node: its name and its sing-box outbound
// options without a tag.
type SubscriptionNode struct {
	Name     string
	Outbound *config.Value
}

// SubscriptionRule is one rule and the policy the subscription sends it to.
type SubscriptionRule struct {
	Policy string
	Rule   *config.Value
}

// MaxExpandedMembers bounds the members subscription members expand to,
// over all groups together: they multiply, a group may name a subscription
// many times and many groups may name it, 1.5. Members written as ids are
// bounded by the size of the document already.
const MaxExpandedMembers = 20000

// NodeTag is the tag a subscription node compiles to.
func NodeTag(subscription, name string) string {
	return tagPrefix + "sub:" + subscription + ":" + name
}

// Compile builds the sing-box configuration for one scenario, or for every
// object when opts.Scenario is empty.
func Compile(c *config.Config, opts Options) (*Result, error) {
	_, r, err := compileScenario(c, opts)
	return r, err
}

// compileScenario is Compile, also returning the compiler's view of the
// scenario, which explain walks.
func compileScenario(c *config.Config, opts Options) (*compiler, *Result, error) {
	if opts.Secret == nil {
		opts.Secret = Placeholder
	}
	if opts.LogLevel == "" {
		opts.LogLevel = "info"
	}
	k := newCompiler(c, opts)

	var scenario *config.Scenario
	if opts.Scenario != "" {
		for _, s := range c.Scenarios {
			if s.ID == opts.Scenario {
				scenario = s
			}
		}
		if scenario == nil {
			return nil, nil, fmt.Errorf("scenario %q does not exist", opts.Scenario)
		}
		for i, r := range scenario.Rules {
			if r.Subscription != "" {
				k.bindSubscription(i, r)
				continue
			}
			k.reach(r.Line)
			k.ruleSets[r.RuleSet] = true
			k.bindings = append(k.bindings, binding{tag: r.RuleSet, line: r.Line, invert: r.Invert, index: i, ruleSet: r.RuleSet, generated: -1})
		}
		k.reach(scenario.Final)
	} else {
		for _, o := range c.Lines {
			k.lines[o.ID] = true
		}
		for _, o := range c.Groups {
			k.lines[o.ID] = true
		}
		for _, o := range c.RuleSets {
			k.ruleSets[o.ID] = true
		}
	}

	doc := map[string]any{
		"log": map[string]any{"level": opts.LogLevel},
	}
	outbounds := []any{map[string]any{"type": "direct", "tag": config.Direct}}
	groups := map[string][]string{}
	var stale []string
	for id := range opts.Selections {
		if o := c.Line(id); o == nil || o.Kind != "group" {
			stale = append(stale, id)
		}
	}
	var endpoints []any
	var endpointIDs []string
	for _, list := range [][]*config.Object{c.Lines, c.Groups} {
		for _, o := range list {
			if !k.lines[o.ID] {
				continue
			}
			v := o.Value.Clone(k.replace).Without("id", "name").With("tag", config.String(o.ID))
			if o.Kind == "line" {
				// Without it sing-box hands a server name to the detour
				// instead of resolving it here, ARCHITECTURE.md 3.3.
				v = v.With("domain_resolver", config.String(tagDNSLocal))
			}
			if o.Kind == "group" {
				members := k.expandMembers(o)
				v = v.With("outbounds", members)
				tags := make([]string, 0, len(members.Items))
				for _, m := range members.Items {
					tags = append(tags, m.String)
				}
				groups[o.ID] = tags
				if picked, ok := opts.Selections[o.ID]; ok {
					if o.Type == "selector" && slices.Contains(tags, picked) {
						v = v.With("default", config.String(picked))
					} else {
						stale = append(stale, o.ID)
					}
				}
			}
			if o.Type == "tailscale" {
				v = v.With("state_directory", config.String(filepath.Join(opts.StateDirectory, o.ID)))
				if key, ok := opts.TailscaleAuthKeys[o.ID]; ok {
					v = v.With("auth_key", config.String(key))
				}
			}
			if o.Kind == "line" && isEndpoint(o.Type) {
				endpoints = append(endpoints, v)
				endpointIDs = append(endpointIDs, o.ID)
			} else {
				outbounds = append(outbounds, v)
			}
		}
	}
	doc["outbounds"] = append(outbounds, k.nodes...)
	if len(endpoints) > 0 {
		doc["endpoints"] = endpoints
	}

	inbounds := k.inbounds()
	if len(inbounds) > 0 {
		doc["inbounds"] = inbounds
	}

	ruleSets, candidates := k.compileRuleSets()
	dns, used := k.dns(scenario, endpointIDs, candidates)
	for _, id := range used {
		set := candidates[id]
		ruleSets = append(ruleSets, map[string]any{"type": "inline", "tag": set.tag, "rules": set.rules})
	}
	doc["route"] = k.route(scenario, endpointIDs, ruleSets)
	doc["dns"] = dns

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(k.pending)
	sort.Strings(k.missing)
	sort.Strings(k.missingSubs)
	sort.Strings(stale)
	var tags []string
	for id := range k.lines {
		tags = append(tags, id)
	}
	tags = append(tags, slices.Collect(maps.Keys(k.nodeSeen))...)
	sort.Strings(tags)
	return k, &Result{JSON: out, Pending: k.pending, MissingRuleSets: k.missing, MissingSubscriptions: k.missingSubs, EmptyGroups: k.empty,
		TooManyMembers: k.tooMany, Endpoints: endpointIDs, Secrets: k.usedSecrets(),
		Groups: groups, Outbounds: tags, StaleSelections: stale}, nil
}

func newCompiler(c *config.Config, opts Options) *compiler {
	k := &compiler{c: c, opts: opts, replace: map[*config.Value]string{}, lines: map[string]bool{}, ruleSets: map[string]bool{},
		subs: map[string]*Subscription{}, nodeSeen: map[string]bool{}}
	for _, use := range c.Secrets {
		k.replace[use.Value] = opts.Secret(use)
	}
	return k
}

// subscription returns the content of subscription id, or nil when it is
// not at hand, which is noted once.
func (k *compiler) subscription(id string) *Subscription {
	if content, ok := k.subs[id]; ok {
		return content
	}
	var content *Subscription
	for _, o := range k.c.Subscriptions {
		if o.ID == id && k.opts.Subscription != nil {
			if got, ok := k.opts.Subscription(o); ok {
				content = got
			}
		}
	}
	if content == nil {
		k.pending = append(k.pending, fmt.Sprintf("订阅 %s 还没下载，检查时用了占位节点", id))
		k.missingSubs = append(k.missingSubs, id)
	}
	k.subs[id] = content
	return content
}

// expandMembers turns the members of group o into outbound tags: ids as
// they are, subscription members into the tags of the nodes their filters
// select, each node compiled once, 1.5.
func (k *compiler) expandMembers(o *config.Object) *config.Value {
	list := &config.Value{Kind: config.KindArray}
	seen := map[string]bool{}
	add := func(tag string, fromSubscription bool) {
		if seen[tag] || k.tooMany {
			return
		}
		if fromSubscription {
			if k.members++; k.members > MaxExpandedMembers {
				k.tooMany = true
				return
			}
		}
		seen[tag] = true
		list.Items = append(list.Items, config.String(tag))
	}
	for _, m := range config.Members(o) {
		if m.Subscription == "" {
			add(m.ID, false)
			continue
		}
		content := k.subscription(m.Subscription)
		if content == nil {
			tag := NodeTag(m.Subscription, "placeholder")
			k.addNode(tag, placeholderNode())
			add(tag, true)
			continue
		}
		filter, _ := regexp.Compile(m.Filter)
		exclude, _ := regexp.Compile(m.Exclude)
		for _, n := range content.Nodes {
			if (m.Filter != "" && !filter.MatchString(n.Name)) || (m.Exclude != "" && exclude.MatchString(n.Name)) {
				continue
			}
			tag := NodeTag(m.Subscription, n.Name)
			if !seen[tag] && !k.tooMany {
				k.addNode(tag, n.Outbound)
			}
			add(tag, true)
		}
	}
	if len(list.Items) == 0 {
		k.empty = append(k.empty, o.ID)
		// sing-box refuses an empty group; the connection is refused
		// before this configuration runs.
		list.Items = append(list.Items, config.String(config.Direct))
	}
	return list
}

func (k *compiler) addNode(tag string, outbound *config.Value) {
	if k.nodeSeen[tag] {
		return
	}
	k.nodeSeen[tag] = true
	v := outbound.Clone(nil).With("tag", config.String(tag)).With("domain_resolver", config.String(tagDNSLocal))
	k.nodes = append(k.nodes, v)
}

func placeholderNode() *config.Value {
	v, _ := config.Parse([]byte(`{"type": "shadowsocks", "server": "` + placeholderDomain + `", "server_port": 443, "method": "aes-128-gcm", "password": "xdial-placeholder"}`))
	return v
}

// bindSubscription compiles a scenario rule that takes a subscription's
// rules: in their order, each to the line its policy maps to, else to
// Other, else left out. Consecutive rules going to the same line share one
// generated rule set, 1.5.
// Only the lines its kept rules go to are reached: a mapping no rule uses
// must not bring a line up, an endpoint least of all.
func (k *compiler) bindSubscription(index int, r config.ScenarioRule) {
	content := k.subscription(r.Subscription)
	if content == nil {
		return
	}
	var run *generatedSet
	var runLine string
	for i, rule := range content.Rules {
		line, ok := r.Policies[rule.Policy]
		if !ok {
			line = r.Other
		}
		if line == "" {
			continue
		}
		if run == nil || line != runLine {
			k.reach(line)
			k.generated = append(k.generated, generatedSet{tag: fmt.Sprintf("%ssub:%s:rules-%d", tagPrefix, r.Subscription, len(k.generated))})
			run = &k.generated[len(k.generated)-1]
			runLine = line
			k.bindings = append(k.bindings, binding{tag: run.tag, line: line, index: index, subscription: r.Subscription, generated: len(k.generated) - 1})
		}
		run.rules = append(run.rules, rule.Rule)
		run.policies = append(run.policies, rule.Policy)
		run.within = append(run.within, i)
	}
}

func isEndpoint(typ string) bool { return typ == "openconnect" || typ == "tailscale" }

// usedSecrets names the secrets of the objects this compilation includes:
// a line or group it reaches, a rule set it routes by, and mixed.
func (k *compiler) usedSecrets() []string {
	compiled := map[string]bool{}
	for _, list := range [][]*config.Object{k.c.Lines, k.c.Groups} {
		for _, o := range list {
			if k.lines[o.ID] {
				compiled[o.Path] = true
			}
		}
	}
	for _, o := range k.c.RuleSets {
		if k.ruleSets[o.ID] {
			compiled[o.Path] = true
		}
	}
	seen := map[string]bool{}
	var names []string
	for _, use := range k.c.Secrets {
		object, _, _ := strings.Cut(use.Path, ".")
		if !compiled[object] && object != "mixed" {
			continue
		}
		if !seen[use.Name] {
			seen[use.Name] = true
			names = append(names, use.Name)
		}
	}
	sort.Strings(names)
	return names
}

// reach marks an outbound and everything it dials through or chooses from.
func (k *compiler) reach(id string) {
	if id == config.Direct || id == config.Block || k.lines[id] {
		return
	}
	o := k.c.Line(id)
	if o == nil {
		return
	}
	k.lines[id] = true
	if d := o.Value.Get("detour"); d != nil {
		k.reach(d.String)
	}
	for _, m := range config.Members(o) {
		if m.Subscription == "" {
			k.reach(m.ID)
		}
	}
}

func (k *compiler) inbounds() []any {
	var inbounds []any
	if k.opts.TUN {
		// ARCHITECTURE.md 6.3: auto_route, no strict_route.
		tun := map[string]any{
			"type":       "tun",
			"tag":        tagTUN,
			"address":    []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route": true,
		}
		if k.opts.Stack != "" {
			tun["stack"] = k.opts.Stack
		}
		inbounds = append(inbounds, tun)
	}
	if m := k.c.Mixed; m != nil {
		mixed := m.Clone(k.replace)
		inbounds = append(inbounds, map[string]any{
			"type":        "mixed",
			"tag":         tagMixed,
			"listen":      "127.0.0.1",
			"listen_port": json.Number(mixed.Get("port").Number),
			"users": []any{map[string]any{
				"username": mixed.Get("username").String,
				"password": mixed.Get("password").String,
			}},
		})
	}
	return inbounds
}

// compileRuleSets returns the rule sets for routing and, for each, the
// candidate DNS-only rule set built from its pure domain rules,
// ARCHITECTURE.md 3.3. A candidate is compiled only if a DNS rule uses it.
func (k *compiler) compileRuleSets() (route []any, dns map[string]dnsSet) {
	dns = map[string]dnsSet{}
	for _, o := range k.c.RuleSets {
		if !k.ruleSets[o.ID] {
			continue
		}
		var rules []*config.Value
		if o.Type == "inline" {
			rules = o.Value.Get("rules").Clone(k.replace).Items
		} else if content, ok := k.remote(o); ok {
			rules = content
		} else {
			rules = []*config.Value{placeholderRule()}
			k.pending = append(k.pending, fmt.Sprintf("规则集 %s 是远程的，检查时用了占位规则，内容在连接前下载", o.ID))
			k.missing = append(k.missing, o.ID)
		}
		route = append(route, k.ruleSet(o.ID, rules, dns))
	}
	for _, g := range k.generated {
		route = append(route, k.ruleSet(g.tag, g.rules, dns))
	}
	return route, dns
}

// ruleSet is one inline rule set for routing; its pure domain rules, if
// any, become the candidate DNS rule set kept in dns under the same tag.
func (k *compiler) ruleSet(tag string, rules []*config.Value, dns map[string]dnsSet) map[string]any {
	var domainRules []*config.Value
	for _, r := range rules {
		if domainOnly(r) {
			domainRules = append(domainRules, r)
		}
	}
	if len(domainRules) > 0 {
		dns[tag] = dnsSet{tag: dnsRuleSet + strings.TrimPrefix(tag, tagPrefix), rules: domainRules, complete: len(domainRules) == len(rules)}
	}
	return map[string]any{"type": "inline", "tag": tag, "rules": rules}
}

type dnsSet struct {
	tag      string
	rules    []*config.Value
	complete bool // every rule of the set is a pure domain rule
}

func (k *compiler) remote(o *config.Object) ([]*config.Value, bool) {
	if k.opts.RuleSet == nil {
		return nil, false
	}
	return k.opts.RuleSet(o)
}

func placeholderRule() *config.Value {
	v, _ := config.Parse([]byte(`{"domain": ["` + placeholderDomain + `"]}`))
	return v
}

// domainOnly reports whether a headless rule decides by domain alone, which
// the DNS stage can evaluate, ARCHITECTURE.md 3.3.
func domainOnly(rule *config.Value) bool {
	if t := rule.Get("type"); t != nil && t.String == "logical" {
		rules := rule.Get("rules")
		if rules == nil || len(rules.Items) == 0 {
			return false
		}
		for _, r := range rules.Items {
			if !domainOnly(r) {
				return false
			}
		}
		return true
	}
	found := false
	for _, f := range rule.Fields {
		switch f.Key {
		case "domain", "domain_suffix", "domain_keyword", "domain_regex":
			found = true
		case "invert", "type":
		default:
			return false
		}
	}
	return found
}

func (k *compiler) route(scenario *config.Scenario, endpointIDs []string, ruleSets []any) map[string]any {
	var rules []any
	if len(endpointIDs) > 0 {
		rules = append(rules, map[string]any{"inbound": endpointIDs, "action": "reject"})
	}
	rules = append(rules,
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
		map[string]any{"action": "resolve"},
	)
	final := config.Direct
	if scenario != nil {
		for _, r := range k.bindings {
			rule := map[string]any{"rule_set": []string{r.tag}}
			if r.invert {
				rule["invert"] = true
			}
			if r.line == config.Block {
				rule["action"] = "reject"
			} else {
				rule["action"] = "route"
				rule["outbound"] = r.line
			}
			rules = append(rules, rule)
		}
	}
	// What a VPN server pushes is remote input: it comes after the user's
	// own rules, block included, and can only claim what final would get.
	for _, id := range endpointIDs {
		rules = append(rules, map[string]any{"preferred_by": []string{id}, "action": "route", "outbound": id})
	}
	if scenario != nil {
		if scenario.Final == config.Block {
			rules = append(rules, map[string]any{"network": []string{"tcp", "udp", "icmp"}, "action": "reject"})
		} else {
			final = scenario.Final
		}
	}
	route := map[string]any{
		"rules":                   rules,
		"final":                   final,
		"auto_detect_interface":   true,
		"default_domain_resolver": tagDNSLocal,
	}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	return route
}

func (k *compiler) dns(scenario *config.Scenario, endpointIDs []string, sets map[string]dnsSet) (map[string]any, []string) {
	var used []string
	seen := map[string]bool{}
	physical := k.opts.PhysicalDNS
	if !physical.IsValid() {
		physical = checkPhysicalDNS
	}
	servers := []any{map[string]any{"type": "udp", "tag": tagDNSLocal, "server": physical.String()}}
	via := map[string]bool{}
	server := func(line string) string {
		o := k.c.Line(line)
		// direct and block use the physical DNS; endpoints answer only the
		// names their VPN pushed, so other names chosen for them use it too,
		// 3.3.
		if o == nil || (o.Kind == "line" && isEndpoint(o.Type)) {
			return tagDNSLocal
		}
		tag := dnsViaPrefix + line
		if !via[line] {
			via[line] = true
			servers = append(servers, map[string]any{"type": "https", "tag": tag, "server": proxyDNSServer, "detour": line})
		}
		return tag
	}

	var rules []any
	if len(endpointIDs) > 0 {
		rules = append(rules, map[string]any{"inbound": endpointIDs, "action": "reject"})
	}
	rules = append(rules, map[string]any{"domain": localNXDOMAIN, "action": "predefined", "rcode": "NXDOMAIN"})
	final := tagDNSLocal
	if scenario != nil {
		for _, r := range k.bindings {
			set, ok := sets[r.tag]
			// DNS rules never reject; blocking happens when routing.
			if !ok || r.line == config.Block || (r.invert && !set.complete) {
				continue
			}
			if !seen[r.tag] {
				seen[r.tag] = true
				used = append(used, r.tag)
			}
			rule := map[string]any{"rule_set": []string{set.tag}, "action": "route", "server": server(r.line)}
			if r.invert {
				rule["invert"] = true
			}
			rules = append(rules, rule)
		}
		if scenario.Final != config.Block {
			final = server(scenario.Final)
		}
	}
	// VPN-pushed names, after the scenario's own rules as in routing.
	for _, id := range endpointIDs {
		tag := dnsEndpoint + id
		servers = append(servers, map[string]any{"type": k.c.Line(id).Type, "tag": tag, "endpoint": id})
		rules = append(rules, map[string]any{"preferred_by": []string{tag}, "action": "route", "server": tag})
	}
	dns := map[string]any{"servers": servers, "final": final, "reverse_mapping": true, "rules": rules}
	return dns, used
}

// CompileDownload builds the configuration a download child runs to fetch
// through line via, ARCHITECTURE.md 3.4: only the chain via reaches, every
// socket bound to iface so it goes around TUN, and server names resolved
// with the physical network's DNS. Config checks keep endpoints out of
// that chain.
func CompileDownload(c *config.Config, via, iface string, opts Options) ([]byte, error) {
	if opts.Secret == nil {
		opts.Secret = Placeholder
	}
	k := newCompiler(c, opts)
	if c.Line(via) == nil {
		return nil, fmt.Errorf("line %q does not exist", via)
	}
	k.reach(via)
	outbounds := []any{map[string]any{"type": "direct", "tag": config.Direct}}
	for _, list := range [][]*config.Object{c.Lines, c.Groups} {
		for _, o := range list {
			if !k.lines[o.ID] {
				continue
			}
			if o.Kind == "line" && isEndpoint(o.Type) {
				return nil, fmt.Errorf("line %q is an endpoint", o.ID)
			}
			v := o.Value.Clone(k.replace).Without("id", "name").With("tag", config.String(o.ID))
			if o.Kind == "line" {
				v = v.With("domain_resolver", config.String(tagDNSLocal))
			}
			outbounds = append(outbounds, v)
		}
	}
	physical := opts.PhysicalDNS
	if !physical.IsValid() {
		physical = checkPhysicalDNS
	}
	return json.Marshal(map[string]any{
		"log":       map[string]any{"disabled": true},
		"outbounds": outbounds,
		"dns": map[string]any{
			"servers": []any{map[string]any{"type": "udp", "tag": tagDNSLocal, "server": physical.String()}},
			"final":   tagDNSLocal,
		},
		"route": map[string]any{
			"final":                   via,
			"default_interface":       iface,
			"default_domain_resolver": tagDNSLocal,
		},
	})
}
