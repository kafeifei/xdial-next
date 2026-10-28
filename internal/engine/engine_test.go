package engine

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/kafeifei/xdial-next/internal/config"
)

// The test binary doubles as the check child, as xdial itself does.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == CheckCommand {
		os.Exit(RunCheckChild(os.Stdin, os.Stdout))
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
		for _, s := range rule["rule_set"].([]any) {
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
