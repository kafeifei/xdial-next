package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Target is what xdial explain is asked about: a domain, an address or a
// URL, ARCHITECTURE.md 3.7.
type Target struct {
	Host string
	Port uint16
}

// ParseTarget reads a domain, an IP address, host:port or a URL.
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return Target{}, fmt.Errorf("不是合法的 URL")
		}
		t := Target{Host: u.Hostname()}
		switch {
		case u.Port() != "":
			port, err := strconv.ParseUint(u.Port(), 10, 16)
			if err != nil {
				return Target{}, fmt.Errorf("端口不对")
			}
			t.Port = uint16(port)
		case u.Scheme == "https":
			t.Port = 443
		case u.Scheme == "http":
			t.Port = 80
		}
		return t, nil
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return Target{}, fmt.Errorf("端口不对")
		}
		return Target{Host: host, Port: uint16(n)}, nil
	}
	if s == "" || strings.ContainsAny(s, " /") {
		return Target{}, fmt.Errorf("写一个域名、IP 地址或 URL")
	}
	return Target{Host: strings.Trim(s, "[]")}, nil
}

// normalized is a host as sing-box matches it: names in lower case and
// without the root's dot, as its DNS hands them over.
func normalized(t Target) Target {
	t.Host = strings.TrimSuffix(strings.ToLower(t.Host), ".")
	return t
}

// Explanation is what xdial explain answers.
type Explanation struct {
	Scenario string `json:"scenario"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	// Addresses are what the host resolved to, when it was resolved;
	// rules on addresses can only match with them.
	Addresses []string `json:"addresses,omitempty"`
	// Rule is the scenario rule that matched; nil means final.
	Rule *RuleMatch `json:"rule,omitempty"`
	// Line is where the traffic goes: a line or group id, direct or block.
	Line string     `json:"line"`
	DNS  *DNSAnswer `json:"dns,omitempty"`
	// Notes say what the answer cannot know.
	Notes []string `json:"notes"`
}

// RuleMatch is the scenario rule that matched.
type RuleMatch struct {
	Index        int    `json:"index"`
	RuleSet      string `json:"rule_set,omitempty"`
	Subscription string `json:"subscription,omitempty"`
	Policy       string `json:"policy,omitempty"`
	// Within is the index of the rule inside the rule set or the
	// subscription's rules that matched, -1 for an inverted match.
	Within int  `json:"within"`
	Invert bool `json:"invert,omitempty"`
}

// DNSAnswer says which DNS server resolves the host and why.
type DNSAnswer struct {
	// Server is "physical", the physical network's DNS, or "via:<line>",
	// DNS over HTTPS through that line, 3.3.
	Server string `json:"server"`
	Reason string `json:"reason"`
	// final is set when no rule chose the server.
	final bool
}

// Explain says where target goes in the scenario opts names, with
// sing-box's own rule implementation, so the answer is what the engine
// would do. addresses are what the host resolved to, if known. The answer
// is for TCP; where UDP, QUIC for one, goes elsewhere, a note says so.
func Explain(c *config.Config, opts Options, target Target, addresses []netip.Addr) (*Explanation, error) {
	target = normalized(target)
	k, result, err := compileScenario(c, opts)
	if err != nil {
		return nil, err
	}
	e := &Explanation{Scenario: opts.Scenario, Host: target.Host, Port: int(target.Port), Notes: []string{}}
	for _, p := range result.Pending {
		e.Notes = append(e.Notes, p+"，按不匹配算")
	}
	metadata := &adapter.InboundContext{}
	if ip, err := netip.ParseAddr(target.Host); err == nil {
		metadata.Destination = M.SocksaddrFrom(ip, target.Port)
	} else {
		metadata.Domain = target.Host
		metadata.Destination = M.Socksaddr{Fqdn: target.Host, Port: target.Port}
		metadata.DestinationAddresses = addresses
		for _, a := range addresses {
			e.Addresses = append(e.Addresses, a.String())
		}
		if len(addresses) == 0 {
			e.Notes = append(e.Notes, "没有解析这个域名：按地址判断的规则按不匹配算")
		}
	}
	if target.Port == 0 {
		e.Notes = append(e.Notes, "没有端口：按端口判断的规则按不匹配算")
	}
	ctx := Context(context.Background())

	scenario := k.scenario()
	metadata.Network = N.NetworkTCP
	rule, line, err := k.explainRoute(ctx, metadata, scenario)
	if err != nil {
		return nil, err
	}
	e.Rule, e.Line = rule, line
	udp := *metadata
	udp.Network = N.NetworkUDP
	udpRule, udpLine, err := k.explainRoute(ctx, &udp, scenario)
	if err != nil {
		return nil, err
	}
	if udpLine != line || !sameRule(udpRule, rule) {
		where := "没有规则命中，走 final"
		if udpRule != nil {
			where = fmt.Sprintf("命中场景第 %d 条规则", udpRule.Index+1)
		}
		e.Notes = append(e.Notes, fmt.Sprintf("以上按 TCP 判断；UDP（例如 QUIC）%s，走 %s", where, udpLine))
	}
	if e.Rule == nil && len(result.Endpoints) > 0 {
		e.Notes = append(e.Notes, "AnyConnect 和 Tailscale 推送的网段和域名只有引擎知道：走 final 的流量可能被它们接管（3.2）")
	}
	if metadata.Domain != "" {
		e.DNS = k.explainDNS(ctx, metadata, scenario)
		if e.DNS.final && len(result.Endpoints) > 0 {
			e.Notes = append(e.Notes, fmt.Sprintf("这个名字如果是 %s 推送的域名，由那条线路的 DNS 解析（3.3）", strings.Join(result.Endpoints, "、")))
		}
	}
	return e, nil
}

// explainRoute finds the first binding metadata matches: the rule and its line,
// or nil and final.
func (k *compiler) explainRoute(ctx context.Context, metadata *adapter.InboundContext, scenario *config.Scenario) (*RuleMatch, string, error) {
	for _, b := range k.bindings {
		rules, policies, within := k.bindingRules(b)
		hit := -1
		for i, r := range rules {
			ok, err := matches(ctx, r, metadata)
			if err != nil {
				return nil, "", err
			}
			if ok {
				hit = i
				break
			}
		}
		if (hit >= 0) == b.invert {
			continue
		}
		m := &RuleMatch{Index: b.index, RuleSet: b.ruleSet, Subscription: b.subscription, Within: hit, Invert: b.invert}
		if hit >= 0 && policies != nil {
			m.Policy, m.Within = policies[hit], within[hit]
		}
		return m, b.line, nil
	}
	return nil, scenario.Final, nil
}

func sameRule(a, b *RuleMatch) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (k *compiler) scenario() *config.Scenario {
	for _, s := range k.c.Scenarios {
		if s.ID == k.opts.Scenario {
			return s
		}
	}
	return nil
}

// bindingRules are the rules of a binding and, for subscription rules,
// their policies and where they stand among the subscription's rules.
func (k *compiler) bindingRules(b binding) ([]*config.Value, []string, []int) {
	if b.generated >= 0 {
		g := k.generated[b.generated]
		return g.rules, g.policies, g.within
	}
	o := k.c.RuleSet(b.ruleSet)
	if o == nil {
		return nil, nil, nil
	}
	if o.Type == "inline" {
		return o.Value.Get("rules").Items, nil, nil
	}
	if rules, ok := k.remote(o); ok {
		return rules, nil, nil
	}
	return nil, nil, nil
}

// matches builds one rule with sing-box and asks it.
func matches(ctx context.Context, r *config.Value, metadata *adapter.InboundContext) (bool, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	var opts option.HeadlessRule
	if err := json.Unmarshal(raw, &opts); err != nil {
		return false, fmt.Errorf("规则读不出来：%w", err)
	}
	built, err := rule.NewHeadlessRule(ctx, opts)
	if err != nil {
		return false, fmt.Errorf("规则建不起来：%w", err)
	}
	m := *metadata
	return built.Match(&m), nil
}

// explainDNS follows the DNS rules compile writes, 3.3: the scenario's
// rules by their pure domain conditions, then final.
func (k *compiler) explainDNS(ctx context.Context, metadata *adapter.InboundContext, scenario *config.Scenario) *DNSAnswer {
	for _, name := range localNXDOMAIN {
		if metadata.Domain == name {
			return &DNSAnswer{Server: "xdial", Reason: "sing-box 自己回 NXDOMAIN（6.4）"}
		}
	}
	for _, b := range k.bindings {
		if b.line == config.Block {
			continue
		}
		rules, _, _ := k.bindingRules(b)
		var domainRules []*config.Value
		for _, r := range rules {
			if domainOnly(r) {
				domainRules = append(domainRules, r)
			}
		}
		if len(domainRules) == 0 || (b.invert && len(domainRules) != len(rules)) {
			continue
		}
		hit := false
		for _, r := range domainRules {
			if ok, _ := matches(ctx, r, &adapter.InboundContext{Domain: metadata.Domain}); ok {
				hit = true
				break
			}
		}
		if hit == b.invert {
			continue
		}
		return &DNSAnswer{Server: k.dnsServerOf(b.line), Reason: fmt.Sprintf("场景第 %d 条规则按域名命中，用它所选线路的 DNS", b.index+1)}
	}
	if scenario.Final == config.Block {
		return &DNSAnswer{Server: "physical", Reason: "没有按域名命中的规则，final 是 block，用物理网络的 DNS", final: true}
	}
	return &DNSAnswer{Server: k.dnsServerOf(scenario.Final), Reason: "没有按域名命中的规则，用 final 线路的 DNS", final: true}
}

// dnsServerOf is the DNS server a line's names resolve with, 3.3.
func (k *compiler) dnsServerOf(line string) string {
	o := k.c.Line(line)
	if o == nil || (o.Kind == "line" && isEndpoint(o.Type)) {
		return "physical"
	}
	return "via:" + line
}
