package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/kafeifei/xdial-next/internal/config"
)

// The test binary doubles as the check child, as xdial itself does.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == CheckCommand {
		os.Exit(RunCheckChild(os.Stdin, os.Stdout))
	}
	if len(os.Args) > 1 && os.Args[1] == EngineCommand {
		os.Exit(RunEngineChild(os.Stdin, os.Stdout, os.Stderr, os.Args[2:]))
	}
	os.Exit(m.Run())
}

func loadFile(t *testing.T, path string) *config.Config {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return loadDoc(t, string(data))
}

func loadDoc(t *testing.T, doc string) *config.Config {
	t.Helper()
	c, problems, err := config.Load([]byte(doc))
	if err != nil || len(problems) > 0 {
		t.Fatalf("load: %v %+v", err, problems)
	}
	return c
}

func compile(t *testing.T, c *config.Config, scenario string) (*Result, map[string]any) {
	t.Helper()
	r, err := Compile(c, Options{Scenario: scenario, StateDirectory: t.TempDir(), TUN: true})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(r.JSON, &doc); err != nil {
		t.Fatal(err)
	}
	return r, doc
}

func TestExampleCompilesAndPassesSingBoxCheck(t *testing.T) {
	c := loadFile(t, "testdata/example.jsonc")
	for _, scenario := range []string{"office", ""} {
		r, _ := compile(t, c, scenario)
		if err := CheckInProcess(r.JSON); err != nil {
			t.Errorf("scenario %q: sing-box check failed: %v\n%s", scenario, err, r.JSON)
		}
		if len(r.Pending) != 1 || !strings.Contains(r.Pending[0], "cn-ip") {
			t.Errorf("scenario %q: pending = %v", scenario, r.Pending)
		}
	}
}

func TestPlaceholdersNeverRealSecrets(t *testing.T) {
	c := loadFile(t, "testdata/example.jsonc")
	r, err := Compile(c, Options{Scenario: "office", StateDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.JSON), `"secret"`) {
		t.Error("a secret reference reached sing-box")
	}
	real, err := Compile(c, Options{Scenario: "office", StateDirectory: t.TempDir(), Secret: func(u config.SecretUse) string { return "real-" + u.Name }})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(real.JSON), "real-hk") {
		t.Error("real secret not substituted")
	}
	// A value that looks like JSON stays a string.
	inject, err := Compile(c, Options{Scenario: "office", StateDirectory: t.TempDir(), Secret: func(config.SecretUse) string { return `x","tls":{"certificate_path":"/etc/hosts"},"y":"` }})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(inject.JSON, &doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(inject.JSON), `"certificate_path":"/etc/hosts"`) {
		t.Error("a secret value broke out of its string")
	}
}

func rules(doc map[string]any, section string) []map[string]any {
	var out []map[string]any
	for _, r := range doc[section].(map[string]any)["rules"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

func TestRouteOrder(t *testing.T) {
	c := loadFile(t, "testdata/example.jsonc")
	_, doc := compile(t, c, "office")
	route := rules(doc, "route")
	actions := []string{}
	for _, r := range route {
		actions = append(actions, r["action"].(string))
	}
	// office reaches corp but not tailnet, so only corp is compiled.
	want := "reject sniff hijack-dns resolve route route route"
	if got := strings.Join(actions, " "); got != want {
		t.Errorf("route is %q, want %q", got, want)
	}
	if in := route[0]["inbound"].([]any); len(in) != 1 || in[0] != "corp" {
		t.Errorf("first rule rejects %v, want the corp endpoint", in)
	}
	// What the VPN pushes is remote input and must not pre-empt the
	// scenario's own rules.
	if route[4]["rule_set"] == nil || route[5]["rule_set"] == nil || route[6]["preferred_by"] == nil {
		t.Error("VPN-pushed routes must come after scenario rules")
	}
	if doc["route"].(map[string]any)["final"] != "proxy" {
		t.Error("final not compiled")
	}
}

func TestDNSRulesComeFromDomainConditionsAndNeverReject(t *testing.T) {
	c := loadDoc(t, `{"version": 1,
		"lines": [{"id": "hk", "type": "trojan", "server": "hk.example", "server_port": 443, "password": {"secret": "hk"}}],
		"rule_sets": [
			{"id": "mixed", "type": "inline", "rules": [{"domain_suffix": ["ads.example"]}, {"ip_cidr": ["203.0.113.0/24"]}]},
			{"id": "ips", "type": "inline", "rules": [{"ip_cidr": ["198.51.100.0/24"]}]},
			{"id": "names", "type": "inline", "rules": [{"domain": ["a.example"]}]}
		],
		"scenarios": [{"id": "s", "rules": [
			{"rule_set": "mixed", "line": "block"},
			{"rule_set": "ips", "line": "hk", "invert": true},
			{"rule_set": "mixed", "line": "hk", "invert": true},
			{"rule_set": "names", "line": "hk", "invert": true},
			{"rule_set": "mixed", "line": "hk"}
		], "final": "block"}]}`)
	r, doc := compile(t, c, "s")
	if err := CheckInProcess(r.JSON); err != nil {
		t.Fatalf("sing-box check failed: %v", err)
	}
	dns := rules(doc, "dns")
	for _, rule := range dns {
		if rule["action"] == "reject" && rule["inbound"] == nil {
			t.Errorf("DNS rule rejects: %v", rule)
		}
	}
	// Only "names" (pure domains, inverted) and "mixed" (its domain rule)
	// produce DNS rules; block, IP-only and partial inverted ones do not.
	var sets []string
	for _, rule := range dns {
		list, _ := rule["rule_set"].([]any)
		for _, s := range list {
			sets = append(sets, s.(string))
		}
	}
	if got := strings.Join(sets, " "); got != "xdial:dns-rules-names xdial:dns-rules-mixed" {
		t.Errorf("DNS rule sets %q", got)
	}
	if doc["dns"].(map[string]any)["final"] != tagDNSLocal {
		t.Error("final block must resolve with local so IP rules can still decide")
	}
	route := rules(doc, "route")
	last := route[len(route)-1]
	if last["action"] != "reject" || last["network"] == nil {
		t.Errorf("final block not compiled to a catch-all reject: %v", last)
	}
}

func TestOnlyReachableObjectsCompile(t *testing.T) {
	c := loadDoc(t, `{"version": 1,
		"lines": [
			{"id": "a", "type": "trojan", "server": "a.example", "server_port": 443, "password": {"secret": "a"}},
			{"id": "b", "type": "trojan", "server": "b.example", "server_port": 443, "password": {"secret": "b"}, "detour": "a"},
			{"id": "ts", "type": "tailscale"}
		],
		"scenarios": [{"id": "s", "rules": [], "final": "b"}]}`)
	_, doc := compile(t, c, "s")
	got := map[string]bool{}
	for _, o := range doc["outbounds"].([]any) {
		got[o.(map[string]any)["tag"].(string)] = true
	}
	if !got["a"] || !got["b"] || doc["endpoints"] != nil {
		t.Errorf("compiled outbounds %v, endpoints %v", got, doc["endpoints"])
	}
	// Every line resolves its server name here, even behind a detour.
	for _, o := range doc["outbounds"].([]any) {
		m := o.(map[string]any)
		if m["tag"] == "b" && m["domain_resolver"] != tagDNSLocal {
			t.Errorf("line b behind a detour has domain_resolver %v", m["domain_resolver"])
		}
	}
}

func TestCheckRunsInAChild(t *testing.T) {
	c := loadFile(t, "testdata/example.jsonc")
	r, _ := compile(t, c, "office")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(context.Background(), exe, r.JSON); err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := Check(context.Background(), exe, []byte(`{"outbounds": [{"type": "tor", "tag": "t"}]}`)); err == nil {
		t.Error("a type outside the registry passed the check")
	}
}

func TestGuardRefusesFilesAndFeatures(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(cert, []byte("not used"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Built by hand, past the classification table, to reach the guard.
	readsFile := `{"outbounds": [{"type": "trojan", "tag": "t", "server": "t.example", "server_port": 443, "password": "x",
		"tls": {"enabled": true, "certificate_path": "` + cert + `"}}]}`
	if err := CheckInProcess([]byte(readsFile)); err == nil || !strings.Contains(err.Error(), "XDial 不允许") {
		t.Errorf("certificate_path read through the guard: %v", err)
	}
	ssh := `{"endpoints": [{"type": "tailscale", "tag": "ts", "state_directory": "` + dir + `", "ssh_server": true}]}`
	if err := CheckInProcess([]byte(ssh)); err == nil || !strings.Contains(err.Error(), "XDial 不允许") {
		t.Errorf("tailscale ssh_server passed the security policy: %v", err)
	}
}

func TestMixedInboundListensOnLoopbackWithUsers(t *testing.T) {
	c := loadFile(t, "testdata/example.jsonc")
	_, doc := compile(t, c, "office")
	var mixed map[string]any
	for _, in := range doc["inbounds"].([]any) {
		if m := in.(map[string]any); m["type"] == "mixed" {
			mixed = m
		}
	}
	if mixed == nil {
		t.Fatal("no mixed inbound")
	}
	users := mixed["users"].([]any)
	if mixed["listen"] != "127.0.0.1" || len(users) != 1 || users[0].(map[string]any)["password"] == "" {
		t.Errorf("mixed inbound must listen on loopback with a user: %v", mixed)
	}
	if mixed["set_system_proxy"] != nil {
		t.Error("mixed inbound must not touch the system proxy")
	}
}

func TestCheckUnavailable(t *testing.T) {
	err := Check(context.Background(), filepath.Join(t.TempDir(), "missing"), []byte("{}"))
	if !errors.Is(err, ErrCheckUnavailable) {
		t.Errorf("err = %v", err)
	}
}

func TestDNSOrderAndUsedSetsOnly(t *testing.T) {
	c := loadDoc(t, `{"version": 1,
		"lines": [
			{"id": "hk", "type": "trojan", "server": "hk.example", "server_port": 443, "password": {"secret": "hk"}},
			{"id": "corp", "type": "openconnect", "server": "https://vpn.example"}
		],
		"rule_sets": [
			{"id": "corp-names", "type": "inline", "rules": [{"domain_suffix": ["corp.example"]}]},
			{"id": "ads", "type": "inline", "rules": [{"domain_suffix": ["ads.example"]}]}
		],
		"scenarios": [{"id": "s", "rules": [
			{"rule_set": "corp-names", "line": "corp"},
			{"rule_set": "ads", "line": "block"}
		], "final": "hk"}]}`)
	r, doc := compile(t, c, "s")
	if err := CheckInProcess(r.JSON); err != nil {
		t.Fatalf("sing-box check failed: %v", err)
	}
	dns := rules(doc, "dns")
	var kinds []string
	for _, rule := range dns {
		switch {
		case rule["inbound"] != nil:
			kinds = append(kinds, "reject-endpoint")
		case rule["action"] == "predefined":
			kinds = append(kinds, "ddr")
		case rule["preferred_by"] != nil:
			kinds = append(kinds, "pushed")
		default:
			kinds = append(kinds, "scenario")
		}
	}
	if got := strings.Join(kinds, " "); got != "reject-endpoint ddr scenario pushed" {
		t.Errorf("DNS rule order %q", got)
	}
	// DDR discovery must fail, or the system upgrades past sing-box, 6.4.
	if dns[1]["rcode"] != "NXDOMAIN" || dns[1]["domain"].([]any)[0] != localNXDOMAIN[0] {
		t.Errorf("DDR rule %v", dns[1])
	}
	// corp is an endpoint: names chosen for it resolve locally, 3.3.
	if dns[2]["server"] != tagDNSLocal {
		t.Errorf("names routed to an endpoint resolve with %v", dns[2]["server"])
	}
	// The block rule's set gets no DNS-only copy.
	for _, set := range doc["route"].(map[string]any)["rule_set"].([]any) {
		if set.(map[string]any)["tag"] == dnsRuleSet+"ads" {
			t.Error("a DNS-only rule set was compiled for a rule no DNS rule uses")
		}
	}
}

// TestCompiledConfigurationStarts goes past box.New, which never resolves
// references between generated parts: starting wires every outbound, rule
// set and DNS server together. TUN, endpoints and mixed are left out, as
// they need root, the network or a free port.
func TestCompiledConfigurationStarts(t *testing.T) {
	c := loadDoc(t, `{"version": 1,
		"lines": [
			{"id": "a", "type": "trojan", "server": "a.example", "server_port": 443, "password": {"secret": "a"}},
			{"id": "b", "type": "vless", "server": "b.example", "server_port": 443, "uuid": {"secret": "b"}, "detour": "a"}
		],
		"groups": [{"id": "proxy", "type": "urltest", "outbounds": ["a", "b"]}],
		"rule_sets": [
			{"id": "names", "type": "inline", "rules": [{"domain_suffix": ["x.example"]}, {"ip_cidr": ["192.0.2.0/24"]}]},
			{"id": "ips", "type": "inline", "rules": [{"ip_cidr": ["198.51.100.0/24"]}]}
		],
		"scenarios": [{"id": "s", "rules": [
			{"rule_set": "names", "line": "proxy"},
			{"rule_set": "ips", "line": "block"},
			{"rule_set": "names", "line": "b", "invert": true}
		], "final": "proxy"}]}`)
	r, err := Compile(c, Options{Scenario: "s", StateDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(Context(context.Background()))
	defer cancel()
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, r.JSON); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Errorf("compiled configuration does not start: %v\n%s", err, r.JSON)
	}
	if err := instance.Close(); err != nil {
		t.Error(err)
	}
}

// TestEngineExitsWhenItsDaemonGoes closes the engine's stdin, as the kernel
// does when the daemon dies, and expects the engine to shut down by itself.
func TestEngineExitsWhenItsDaemonGoes(t *testing.T) {
	c := loadDoc(t, `{"version": 1, "lines": [], "scenarios": [{"id": "s", "rules": [], "final": "direct"}]}`)
	r, err := Compile(c, Options{Scenario: "s", StateDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, EngineCommand)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(r.JSON); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadBytes('\n')
	if err != nil || !strings.Contains(string(line), `"ready":true`) {
		t.Fatalf("engine not ready: %q %v", line, err)
	}
	stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("engine exited with %v", err)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("engine kept running after its stdin closed")
	}
}

func TestCompileDownloadHoldsOnlyTheChain(t *testing.T) {
	c := loadDoc(t, `{"version": 1,
		"lines": [
			{"id": "front", "type": "shadowsocks", "server": "front.example", "server_port": 443, "method": "aes-128-gcm", "password": {"secret": "f"}},
			{"id": "hk", "type": "trojan", "server": "hk.example", "server_port": 443, "password": {"secret": "hk"}, "detour": "front"},
			{"id": "jp", "type": "trojan", "server": "jp.example", "server_port": 443, "password": {"secret": "jp"}},
			{"id": "corp", "type": "openconnect", "flavor": "anyconnect", "server": "https://vpn.example", "username": "u", "password": {"secret": "c"}}
		],
		"groups": [{"id": "proxy", "type": "urltest", "outbounds": ["hk"]}],
		"rule_sets": [{"id": "r", "type": "remote", "format": "binary", "url": "https://rules.example/r.srs", "download_via": "proxy"}],
		"scenarios": [{"id": "s", "rules": [{"rule_set": "r", "line": "corp"}], "final": "jp"}]}`)
	out, err := CompileDownload(c, "proxy", "en0", Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []any            `json:"endpoints"`
		Inbounds  []any            `json:"inbounds"`
		Route     map[string]any   `json:"route"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, o := range doc.Outbounds {
		tags = append(tags, o["tag"].(string))
	}
	if strings.Join(tags, ",") != "direct,front,hk,proxy" || doc.Endpoints != nil || doc.Inbounds != nil {
		t.Errorf("download configuration holds more than the chain: %s", out)
	}
	if doc.Route["final"] != "proxy" || doc.Route["default_interface"] != "en0" {
		t.Errorf("route: %v", doc.Route)
	}
	if err := CheckInProcess(out); err != nil {
		t.Errorf("sing-box rejects it: %v", err)
	}
	if _, err := CompileDownload(c, "corp", "en0", Options{}); err == nil {
		t.Error("an endpoint was compiled into a download")
	}
}

const subscriptionDoc = `{"version": 1,
	"lines": [{"id": "jp", "type": "trojan", "server": "jp.example", "server_port": 443, "password": {"secret": "jp"}}],
	"groups": [{"id": "proxy", "type": "urltest", "outbounds": [{"subscription": "air", "filter": "香港", "exclude": "剩余"}, "jp"]}],
	"subscriptions": [{"id": "air", "url": {"secret": "air-url"}}],
	"scenarios": [{"id": "s", "rules": [{"subscription": "air", "policies": {"Proxy": "proxy", "DIRECT": "direct", "REJECT": "block"}}], "final": "direct"},
	              {"id": "o", "rules": [{"subscription": "air", "policies": {"Proxy": "proxy"}, "other": "direct"}], "final": "proxy"}]}`

func airContent(t *testing.T) *Subscription {
	t.Helper()
	parse := func(s string) *config.Value {
		v, err := config.Parse([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	node := func(server string) *config.Value {
		return parse(`{"type": "shadowsocks", "server": "` + server + `", "server_port": 8388, "method": "aes-128-gcm", "password": "p"}`)
	}
	return &Subscription{
		Nodes: []SubscriptionNode{
			{Name: "香港 01", Outbound: node("hk1.example")}, {Name: "日本", Outbound: node("jp.example")},
			{Name: "香港 02", Outbound: node("hk2.example")}, {Name: "香港 剩余流量", Outbound: node("info.example")},
		},
		Rules: []SubscriptionRule{
			{Policy: "Proxy", Rule: parse(`{"domain_suffix": ["google.com"]}`)},
			{Policy: "Proxy", Rule: parse(`{"domain_suffix": ["youtube.com"]}`)},
			{Policy: "DIRECT", Rule: parse(`{"domain": ["a.example"]}`)},
			{Policy: "REJECT", Rule: parse(`{"domain_keyword": ["ads"]}`)},
			{Policy: "Elsewhere", Rule: parse(`{"ip_cidr": ["10.0.0.0/8"]}`)},
		},
	}
}

func TestCompileSubscription(t *testing.T) {
	c := loadDoc(t, subscriptionDoc)
	content := airContent(t)
	r, err := Compile(c, Options{Scenario: "s", StateDirectory: t.TempDir(), TUN: true,
		Subscription: func(*config.Object) (*Subscription, bool) { return content, true }})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules   []map[string]any `json:"rules"`
			RuleSet []map[string]any `json:"rule_set"`
		} `json:"route"`
		DNS struct {
			Rules []map[string]any `json:"rules"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(r.JSON, &doc); err != nil {
		t.Fatal(err)
	}
	var tags []string
	var group []any
	for _, o := range doc.Outbounds {
		tags = append(tags, o["tag"].(string))
		if o["tag"] == "proxy" {
			group = o["outbounds"].([]any)
		}
		if strings.HasPrefix(o["tag"].(string), "xdial:sub:") && o["domain_resolver"] != "xdial:dns-local" {
			t.Errorf("node without the physical resolver: %v", o)
		}
	}
	if got := fmt.Sprint(group); got != "[xdial:sub:air:香港 01 xdial:sub:air:香港 02 jp]" {
		t.Errorf("group members: %s", got)
	}
	if strings.Contains(strings.Join(tags, ","), "日本") || strings.Contains(strings.Join(tags, ","), "剩余") {
		t.Errorf("unselected nodes compiled: %v", tags)
	}
	var routes []string
	for _, rule := range doc.Route.Rules {
		if sets, ok := rule["rule_set"].([]any); ok {
			routes = append(routes, fmt.Sprintf("%v→%v %v", sets[0], rule["outbound"], rule["action"]))
		}
	}
	want := "[xdial:sub:air:rules-0→proxy route xdial:sub:air:rules-1→direct route xdial:sub:air:rules-2→<nil> reject]"
	if fmt.Sprint(routes) != want {
		t.Errorf("route rules: %v", routes)
	}
	var dnsSets []string
	for _, rule := range doc.DNS.Rules {
		if sets, ok := rule["rule_set"].([]any); ok {
			dnsSets = append(dnsSets, fmt.Sprint(sets[0]))
		}
	}
	if fmt.Sprint(dnsSets) != "[xdial:dns-rules-sub:air:rules-0 xdial:dns-rules-sub:air:rules-1]" {
		t.Errorf("dns rules: %v", dnsSets)
	}
	if err := CheckInProcess(r.JSON); err != nil {
		t.Errorf("sing-box rejects it: %v", err)
	}

	// other takes the rules of every unmapped policy.
	r, err = Compile(c, Options{Scenario: "o", StateDirectory: t.TempDir(), TUN: true,
		Subscription: func(*config.Object) (*Subscription, bool) { return content, true }})
	if err != nil {
		t.Fatal(err)
	}
	// Proxy goes to proxy; DIRECT, REJECT and Elsewhere all fall to other
	// and, consecutive, share one rule set.
	var sets struct {
		Route struct {
			RuleSet []struct {
				Tag   string `json:"tag"`
				Rules []any  `json:"rules"`
			} `json:"rule_set"`
		} `json:"route"`
	}
	_ = json.Unmarshal(r.JSON, &sets)
	var got []string
	for _, s := range sets.Route.RuleSet {
		got = append(got, fmt.Sprintf("%s:%d", s.Tag, len(s.Rules)))
	}
	if fmt.Sprint(got) != "[xdial:sub:air:rules-0:2 xdial:sub:air:rules-1:3 xdial:dns-rules-sub:air:rules-0:2 xdial:dns-rules-sub:air:rules-1:2]" {
		t.Errorf("rule sets with other: %v", got)
	}
}

func TestCompileSubscriptionMissingOrEmpty(t *testing.T) {
	// Scenario o ends at the group, so the group and its placeholder node
	// are compiled; its subscription rules, without content, add nothing.
	c := loadDoc(t, subscriptionDoc)
	r, err := Compile(c, Options{Scenario: "o", StateDirectory: t.TempDir(), TUN: true})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(r.MissingSubscriptions) != "[air]" || len(r.Pending) == 0 || !strings.Contains(string(r.JSON), "xdial:sub:air:placeholder") {
		t.Errorf("missing: %v pending %v", r.MissingSubscriptions, r.Pending)
	}
	if err := CheckInProcess(r.JSON); err != nil {
		t.Errorf("the placeholder configuration fails the check: %v", err)
	}
	empty := strings.Replace(subscriptionDoc, `"filter": "香港"`, `"filter": "nothing matches"`, 1)
	empty = strings.Replace(empty, `, "jp"]`, `]`, 1)
	r, err = Compile(loadDoc(t, empty), Options{Scenario: "s", StateDirectory: t.TempDir(), TUN: true,
		Subscription: func(*config.Object) (*Subscription, bool) { return airContent(t), true }})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(r.EmptyGroups) != "[proxy]" {
		t.Errorf("empty groups: %v", r.EmptyGroups)
	}
}

func TestCompileSubscriptionBounds(t *testing.T) {
	// Repeated references collapse; an unused mapping reaches nothing.
	doc := strings.Replace(subscriptionDoc, `[{"subscription": "air", "filter": "香港", "exclude": "剩余"}, "jp"]`,
		`[{"subscription": "air"}, {"subscription": "air"}, "jp", "jp"]`, 1)
	doc = strings.Replace(doc, `"other": "direct"`, `"other": "proxy"`, 1)
	c := loadDoc(t, doc)
	content := airContent(t)
	r, err := Compile(c, Options{Scenario: "s", StateDirectory: t.TempDir(), TUN: true,
		Subscription: func(*config.Object) (*Subscription, bool) { return content, true }})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	_ = json.Unmarshal(r.JSON, &out)
	for _, o := range out.Outbounds {
		if o["tag"] == "proxy" && len(o["outbounds"].([]any)) != 5 {
			t.Errorf("members not deduplicated: %v", o["outbounds"])
		}
	}
	// Scenario s maps Proxy, DIRECT and REJECT; a scenario whose rules all
	// go elsewhere must not bring jp up through an unused mapping.
	unused := loadDoc(t, strings.Replace(subscriptionDoc, `"policies": {"Proxy": "proxy", "DIRECT": "direct", "REJECT": "block"}`,
		`"policies": {"Proxy": "direct", "DIRECT": "direct", "REJECT": "block", "Nobody": "jp"}`, 1))
	r, err = Compile(unused, Options{Scenario: "s", StateDirectory: t.TempDir(), TUN: true,
		Subscription: func(*config.Object) (*Subscription, bool) { return content, true }})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.JSON), `"tag":"jp"`) {
		t.Error("a mapping no rule uses compiled its line")
	}
	// Many groups naming a large subscription stop at the budget.
	big := &Subscription{}
	for i := range 2000 {
		big.Nodes = append(big.Nodes, SubscriptionNode{Name: fmt.Sprint("n", i), Outbound: content.Nodes[0].Outbound})
	}
	var groups []string
	for i := range 20 {
		groups = append(groups, fmt.Sprintf(`{"id": "g%d", "type": "selector", "outbounds": [{"subscription": "air"}]}`, i))
	}
	var finals []string
	for i := range 20 {
		finals = append(finals, fmt.Sprintf(`{"id": "s%d", "rules": [], "final": "g%d"}`, i, i))
	}
	many := loadDoc(t, `{"version": 1, "groups": [`+strings.Join(groups, ",")+`],
		"subscriptions": [{"id": "air", "url": {"secret": "u"}}], "scenarios": [`+strings.Join(finals, ",")+`]}`)
	r, err = Compile(many, Options{StateDirectory: t.TempDir(),
		Subscription: func(*config.Object) (*Subscription, bool) { return big, true }})
	if err != nil {
		t.Fatal(err)
	}
	if !r.TooManyMembers {
		t.Error("20 groups of 2000 nodes did not hit the member budget")
	}
}

func TestPlainMembersDoNotCountAgainstTheBudget(t *testing.T) {
	var lines, members, groups []string
	for i := range 200 {
		lines = append(lines, fmt.Sprintf(`{"id": "l%d", "type": "trojan", "server": "a.example", "server_port": 443, "password": {"secret": "p"}}`, i))
		members = append(members, fmt.Sprintf(`"l%d"`, i))
	}
	for i := range 101 {
		groups = append(groups, fmt.Sprintf(`{"id": "g%d", "type": "selector", "outbounds": [%s]}`, i, strings.Join(members, ",")))
	}
	c := loadDoc(t, `{"version": 1, "lines": [`+strings.Join(lines, ",")+`], "groups": [`+strings.Join(groups, ",")+`],
		"scenarios": [{"id": "s", "final": "g0"}]}`)
	r, err := Compile(c, Options{StateDirectory: t.TempDir()})
	if err != nil || r.TooManyMembers {
		t.Errorf("20,200 members written by hand hit the subscription budget: %v", err)
	}
}

func TestAuthKeyIsCompiledOnlyWhenGiven(t *testing.T) {
	c := loadDoc(t, `{"version": 1, "lines": [{"id": "tailnet", "type": "tailscale"}],
		"scenarios": [{"id": "s", "final": "tailnet"}]}`)
	plain, err := Compile(c, Options{Scenario: "s", StateDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain.JSON), "auth_key") {
		t.Error("an auth key appeared without a login")
	}
	login, err := Compile(c, Options{Scenario: "s", StateDirectory: t.TempDir(), TailscaleAuthKeys: map[string]string{"tailnet": "tskey-auth-xyz"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(login.JSON), `"auth_key":"tskey-auth-xyz"`) {
		t.Errorf("the auth key is missing: %s", login.JSON)
	}
}

func TestEngineIgnoresACommandForNoSuchLine(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, EngineCommand)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_, _ = stdin.Write([]byte(`{"log": {"level": "error"}, "outbounds": [{"type": "direct", "tag": "direct"}],
		"dns": {"servers": [{"type": "udp", "tag": "d", "server": "192.0.2.53"}], "final": "d"}}` + "\n"))
	line, _ := bufio.NewReader(stdout).ReadBytes('\n')
	if !strings.Contains(string(line), `"ready":true`) {
		t.Fatalf("engine did not start: %q", line)
	}
	_, _ = stdin.Write([]byte(`{"tailscale_logout": "nope"}` + "\n"))
	time.Sleep(200 * time.Millisecond)
	_ = stdin.Close() // the daemon going away ends the engine
	if err := cmd.Wait(); err != nil {
		t.Errorf("engine exit: %v, stderr %s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no tailscale line nope") {
		t.Errorf("stderr: %s", stderr.String())
	}
}

func TestStatusTextIsBoundedButFarAboveWhatIsKept(t *testing.T) {
	if got := bound(strings.Repeat("x", 2<<20)); len(got) != maxText {
		t.Errorf("bounded to %d bytes", len(got))
	}
	if maxText <= 4096 {
		t.Error("the engine's bound must stay far above what the daemon keeps")
	}
}

// TestGroupsReportAndTestThroughNesting runs groups inside groups: a
// member that is a group shows the result its group keeps under the line
// it leads to, and a test reaches every line however deep.
func TestGroupsReportAndTestThroughNesting(t *testing.T) {
	c := loadDoc(t, `{"version": 1,
		"lines": [
			{"id": "a", "type": "trojan", "server": "127.0.0.1", "server_port": 9, "password": {"secret": "a"}},
			{"id": "b", "type": "trojan", "server": "127.0.0.1", "server_port": 9, "password": {"secret": "a"}}
		],
		"groups": [
			{"id": "outer", "type": "urltest", "outbounds": ["inner", "a"]},
			{"id": "inner", "type": "selector", "outbounds": ["b"]},
			{"id": "g0", "type": "selector", "outbounds": ["g1"]},
			{"id": "g1", "type": "selector", "outbounds": ["g2"]},
			{"id": "g2", "type": "selector", "outbounds": ["g3"]},
			{"id": "g3", "type": "selector", "outbounds": ["g4"]},
			{"id": "g4", "type": "selector", "outbounds": ["a", "b"]}
		],
		"rule_sets": [{"id": "x", "type": "inline", "rules": [{"domain": ["x.example"]}]}],
		"scenarios": [{"id": "s", "rules": [{"rule_set": "x", "line": "g0"}], "final": "outer"}]}`)
	r, err := Compile(c, Options{Scenario: "s", StateDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	history := urltest.NewHistoryStorage()
	ctx, cancel := context.WithCancel(service.ContextWithPtr(Context(context.Background()), history))
	defer cancel()
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, r.JSON); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	rep := newReporter(instance, history, io.Discard, io.Discard)
	history.StoreURLTestHistory("b", &adapter.URLTestHistory{Time: time.Now(), Delay: 42})
	for _, m := range rep.groups()["outer"].Members {
		if m.Tag == "inner" && m.DelayMS != 42 {
			t.Errorf("inner in outer: %+v", m)
		}
	}
	results := urlTest(ctx, instance, rep, []string{"g0"})
	if len(results) != 2 || results["a"].Error == "" || results["b"].Error == "" {
		t.Errorf("test of g0: %v", results)
	}
}
