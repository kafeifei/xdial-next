package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"

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
