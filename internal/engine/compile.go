// Package engine turns a checked configuration into the sing-box
// configuration XDial runs, following ARCHITECTURE.md section 3, and checks
// it with sing-box itself through a restricted registry (section 2.3).
package engine

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
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
	// TUN adds the TUN inbound, with Stack as its implementation.
	TUN   bool
	Stack string
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
	// Secrets names the secrets the compiled objects use, sorted.
	Secrets []string
}

type compiler struct {
	c        *config.Config
	opts     Options
	replace  map[*config.Value]string
	pending  []string
	missing  []string
	lines    map[string]bool // outbounds to compile
	ruleSets map[string]bool
}

// Compile builds the sing-box configuration for one scenario, or for every
// object when opts.Scenario is empty.
func Compile(c *config.Config, opts Options) (*Result, error) {
	if opts.Secret == nil {
		opts.Secret = Placeholder
	}
	if opts.LogLevel == "" {
		opts.LogLevel = "info"
	}
	k := &compiler{c: c, opts: opts, replace: map[*config.Value]string{}, lines: map[string]bool{}, ruleSets: map[string]bool{}}
	for _, use := range c.Secrets {
		k.replace[use.Value] = opts.Secret(use)
	}

	var scenario *config.Scenario
	if opts.Scenario != "" {
		for _, s := range c.Scenarios {
			if s.ID == opts.Scenario {
				scenario = s
			}
		}
		if scenario == nil {
			return nil, fmt.Errorf("scenario %q does not exist", opts.Scenario)
		}
		for _, r := range scenario.Rules {
			k.reach(r.Line)
			k.ruleSets[r.RuleSet] = true
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
			if o.Type == "tailscale" {
				v = v.With("state_directory", config.String(filepath.Join(opts.StateDirectory, o.ID)))
			}
			if o.Kind == "line" && isEndpoint(o.Type) {
				endpoints = append(endpoints, v)
				endpointIDs = append(endpointIDs, o.ID)
			} else {
				outbounds = append(outbounds, v)
			}
		}
	}
	doc["outbounds"] = outbounds
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
		return nil, err
	}
	sort.Strings(k.pending)
	sort.Strings(k.missing)
	return &Result{JSON: out, Pending: k.pending, MissingRuleSets: k.missing, Secrets: k.usedSecrets()}, nil
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
	if members := o.Value.Get("outbounds"); members != nil {
		for _, m := range members.Items {
			k.reach(m.String)
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
			k.pending = append(k.pending, fmt.Sprintf("规则集 %s 的内容还没下载，检查时用了占位规则", o.ID))
			k.missing = append(k.missing, o.ID)
		}
		route = append(route, map[string]any{"type": "inline", "tag": o.ID, "rules": rules})

		var domainRules []*config.Value
		for _, r := range rules {
			if domainOnly(r) {
				domainRules = append(domainRules, r)
			}
		}
		if len(domainRules) > 0 {
			dns[o.ID] = dnsSet{tag: dnsRuleSet + o.ID, rules: domainRules, complete: len(domainRules) == len(rules)}
		}
	}
	return route, dns
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
		for _, r := range scenario.Rules {
			rule := map[string]any{"rule_set": []string{r.RuleSet}}
			if r.Invert {
				rule["invert"] = true
			}
			if r.Line == config.Block {
				rule["action"] = "reject"
			} else {
				rule["action"] = "route"
				rule["outbound"] = r.Line
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
		for _, r := range scenario.Rules {
			set, ok := sets[r.RuleSet]
			// DNS rules never reject; blocking happens when routing.
			if !ok || r.Line == config.Block || (r.Invert && !set.complete) {
				continue
			}
			if !seen[r.RuleSet] {
				seen[r.RuleSet] = true
				used = append(used, r.RuleSet)
			}
			rule := map[string]any{"rule_set": []string{set.tag}, "action": "route", "server": server(r.Line)}
			if r.Invert {
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
