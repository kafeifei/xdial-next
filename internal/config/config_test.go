package config

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/kafeifei/xdial-next/internal/cli"
)

func TestParseAcceptsCommentsAndTrailingCommas(t *testing.T) {
	v, err := Parse([]byte(`// leading
	{
		# hash comment
		"a": [1, 2, /* inline */ 3,],
		"b": {"c": "é😀",},
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(v.Get("a").Items); got != 3 {
		t.Errorf("a has %d items", got)
	}
	if got := v.Get("b").Get("c").String; got != "é😀" {
		t.Errorf("c = %q", got)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"duplicate key":  `{"a": 1, "a": 2}`,
		"bom":            "\xEF\xBB\xBF{}",
		"invalid utf-8":  "{\"a\": \"\xff\"}",
		"go escape":      `{"a": "\x41"}`,
		"control char":   "{\"a\": \"x\ty\"}",
		"trailing data":  `{} {}`,
		"bad number":     `{"a": 01}`,
		"open comment":   `{"a": 1 /* }`,
		"single quotes":  `{'a': 1}`,
		"unquoted key":   `{a: 1}`,
		"missing value":  `{"a": }`,
		"truncated":      `{"a": [1, 2`,
		"deep nesting":   strings.Repeat("[", maxDepth+2) + strings.Repeat("]", maxDepth+2),
		"empty document": ``,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func load(t *testing.T, doc string) (*Config, []cli.Problem) {
	t.Helper()
	c, problems, err := Load([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return c, problems
}

// TestArchitectureExample keeps the example in ARCHITECTURE.md 1.2 valid
// and identical to testdata/example.jsonc.
func TestArchitectureExample(t *testing.T) {
	data, err := os.ReadFile("testdata/example.jsonc")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../ARCHITECTURE.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)### 1\\.2 示例\n\n```jsonc\n(.*?)```").FindSubmatch(doc)
	if m == nil {
		t.Fatal("ARCHITECTURE.md has no example in 1.2")
	}
	if !strings.HasSuffix(string(data), string(m[1])) {
		t.Error("testdata/example.jsonc differs from the example in ARCHITECTURE.md 1.2")
	}
	c, problems := load(t, string(data))
	if len(problems) > 0 {
		t.Fatalf("example has problems: %+v", problems)
	}
	if len(c.Lines) != 4 || len(c.Groups) != 1 || len(c.RuleSets) != 2 || len(c.Scenarios) != 1 {
		t.Errorf("unexpected objects: %d lines, %d groups, %d rule sets, %d scenarios", len(c.Lines), len(c.Groups), len(c.RuleSets), len(c.Scenarios))
	}
	names := map[string]bool{}
	for _, s := range c.Secrets {
		names[s.Name] = true
	}
	for _, want := range []string{"mixed", "hk", "jp", "corp", "airport-url"} {
		if !names[want] {
			t.Errorf("secret %q not collected", want)
		}
	}
}

const base = `{"version": 1, "lines": [%s], "groups": [%s], "rule_sets": [{"id": "r", "type": "inline", "rules": [{"domain": ["a.example"]}]}%s], "scenarios": [{"id": "s", "rules": [{"rule_set": "r", "line": "direct"}], "final": "%s"}]}`

func build(lines, groups, ruleSets, final string) string {
	if final == "" {
		final = "direct"
	}
	if ruleSets != "" {
		ruleSets = "," + ruleSets
	}
	parts := strings.SplitN(base, "%s", 5)
	return parts[0] + lines + parts[1] + groups + parts[2] + ruleSets + parts[3] + final + parts[4]
}

const trojan = `{"id": "hk", "type": "trojan", "server": "hk.example.com", "server_port": 443, "password": {"secret": "hk"}%s}`

func line(extra string) string { return strings.Replace(trojan, "%s", extra, 1) }

func codes(problems []cli.Problem) string {
	var list []string
	for _, p := range problems {
		list = append(list, p.Code+"@"+p.Path)
	}
	return strings.Join(list, " ")
}

func TestLoadProblems(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string // a code@path that must be among the problems
	}{
		{"inline secret", build(`{"id": "hk", "type": "trojan", "server": "h.example", "server_port": 443, "password": "x"}`, "", "", ""), "config.secret_inline@lines[0].password"},
		{"secret ref with extra key", build(line(`, "uuid": 1`), "", "", ""), "config.unknown_key@lines[0].uuid"},
		{"case folded key", build(line(`, "TLS": {}`), "", "", ""), "config.unknown_key@lines[0].TLS"},
		{"long s folding", build(line(`, "tls": {"enabled": true, "ſerver_name": "x.example"}`), "", "", ""), "config.unknown_key@lines[0].tls.ſerver_name"},
		{"forbidden path", build(line(`, "tls": {"certificate_path": "/etc/hosts"}`), "", "", ""), "config.forbidden_key@lines[0].tls.certificate_path"},
		{"forbidden even when empty", build(line(`, "tls": {"certificate_path": ""}`), "", "", ""), "config.forbidden_key@lines[0].tls.certificate_path"},
		{"generated field", build(line(`, "bind_interface": "en0"`), "", "", ""), "config.forbidden_key@lines[0].bind_interface"},
		{"protect path", build(line(`, "protect_path": "/tmp/x"`), "", "", ""), "config.forbidden_key@lines[0].protect_path"},
		{"spoof", build(line(`, "tls": {"spoof": "x"}`), "", "", ""), "config.forbidden_key@lines[0].tls.spoof"},
		{"tag", build(line(`, "tag": "x"`), "", "", ""), "config.forbidden_key@lines[0].tag"},
		{"type not allowed", build(`{"id": "t", "type": "tor"}`, "", "", ""), "config.type_not_allowed@lines[0].type"},
		{"direct as a line type", build(`{"id": "d", "type": "direct"}`, "", "", ""), "config.type_not_allowed@lines[0].type"},
		{"missing server", build(`{"id": "hk", "type": "trojan", "server_port": 443, "password": {"secret": "hk"}}`, "", "", ""), "config.value@lines[0].server"},
		{"negative duration", build(line(`, "connect_timeout": "-1s"`), "", "", ""), "config.value@lines[0].connect_timeout"},
		{"zero duration", build("", `{"id": "g", "type": "urltest", "outbounds": ["direct"], "interval": "0s"}`, "", ""), "config.value@groups[0].interval"},
		{"non-PEM certificate", build(line(`, "tls": {"certificate": "not a certificate"}`), "", "", ""), "config.value@lines[0].tls.certificate"},
		{"port out of range", build(`{"id": "hk", "type": "trojan", "server": "h.example", "server_port": 70000, "password": {"secret": "hk"}}`, "", "", ""), "config.value@lines[0].server_port"},
		{"bad secret name", build(`{"id": "hk", "type": "trojan", "server": "h.example", "server_port": 443, "password": {"secret": "Bad Name"}}`, "", "", ""), "config.value@lines[0].password.secret"},
		{"reserved id", build(`{"id": "direct", "type": "trojan", "server": "h.example", "server_port": 443, "password": {"secret": "hk"}}`, "", "", ""), "config.duplicate_id@lines[0].id"},
		{"duplicate id across lines and groups", build(line(""), `{"id": "hk", "type": "selector", "outbounds": ["direct"]}`, "", ""), "config.duplicate_id@groups[0].id"},
		{"missing member", build("", `{"id": "g", "type": "selector", "outbounds": ["nope"]}`, "", ""), "config.reference@groups[0].outbounds[0]"},
		{"block as a member", build("", `{"id": "g", "type": "selector", "outbounds": ["block"]}`, "", ""), "config.reference@groups[0].outbounds[0]"},
		{"default not a member", build(line(""), `{"id": "g", "type": "selector", "outbounds": ["direct"], "default": "hk"}`, "", ""), "config.reference@groups[0].default"},
		{"missing final", build("", "", "", "nope"), "config.reference@scenarios[0].final"},
		{"cycle", build(line(`, "detour": "g"`), `{"id": "g", "type": "selector", "outbounds": ["hk"]}`, "", ""), "config.cycle@"},
		{"download via endpoint", build(`{"id": "corp", "type": "openconnect", "server": "https://vpn.example"}`, `{"id": "g", "type": "selector", "outbounds": ["corp"]}`, `{"id": "x", "type": "remote", "format": "binary", "url": "https://e.example/x.srs", "download_via": "g"}`, ""), "config.reference@rule_sets[1].download_via"},
		{"remote url over http", build("", "", `{"id": "x", "type": "remote", "format": "binary", "url": "http://e.example/x.srs"}`, ""), "config.value@rule_sets[1].url"},
		{"local rule set", build("", "", `{"id": "x", "type": "local", "path": "/etc/hosts"}`, ""), "config.type_not_allowed@rule_sets[1].type"},
		{"plugin cert", build(`{"id": "ss", "type": "shadowsocks", "server": "s.example", "server_port": 8388, "method": "aes-128-gcm", "password": {"secret": "ss"}, "plugin": "v2ray-plugin", "plugin_opts": "tls;cert=/etc/hosts"}`, "", "", ""), "config.value@lines[0].plugin_opts"},
		{"tailscale ssh", build(`{"id": "ts", "type": "tailscale", "ssh_server": true}`, "", "", ""), "config.forbidden_key@lines[0].ssh_server"},
		{"openconnect wrapper", build(`{"id": "oc", "type": "openconnect", "server": "https://vpn.example", "csd": {"wrapper_path": "/bin/sh"}}`, "", "", ""), "config.forbidden_key@lines[0].csd"},
		{"unknown top-level key", `{"version": 1, "inbounds": [], "scenarios": []}`, "config.unknown_key@inbounds"},
		{"logical rule without rules", build("", "", `{"id": "x", "type": "inline", "rules": [{"type": "logical", "mode": "and"}]}`, ""), "config.value@rule_sets[1].rules[0].rules"},
		{"header name with escape", build(`{"id": "v", "type": "vless", "server": "v.example", "server_port": 443, "uuid": {"secret": "v"}, "transport": {"type": "ws", "headers": {"\u001b[31m": "x"}}}`, "", "", ""), "config.value@lines[0].transport.headers.\x1b[31m"},
		{"reality short id too long", build(`{"id": "v", "type": "vless", "server": "v.example", "server_port": 443, "uuid": {"secret": "v"}, "tls": {"enabled": true, "utls": {"enabled": true}, "reality": {"enabled": true, "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", "short_id": "0123456789abcdef01"}}}`, "", "", ""), "config.value@lines[0].tls.reality.short_id"},
		{"reality bad public key", build(`{"id": "v", "type": "vless", "server": "v.example", "server_port": 443, "uuid": {"secret": "v"}, "tls": {"enabled": true, "utls": {"enabled": true}, "reality": {"enabled": true, "public_key": "short"}}}`, "", "", ""), "config.value@lines[0].tls.reality.public_key"},
		{"reality without utls", build(`{"id": "v", "type": "vless", "server": "v.example", "server_port": 443, "uuid": {"secret": "v"}, "tls": {"enabled": true, "reality": {"enabled": true, "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"}}}`, "", "", ""), "config.value@lines[0].tls.utls"},
		{"urltest interval above idle timeout", build("", `{"id": "g", "type": "urltest", "outbounds": ["direct"], "interval": "2m", "idle_timeout": "1m"}`, "", ""), "config.value@groups[0].interval"},
		{"tls versions crossed", build(line(`, "tls": {"enabled": true, "min_version": "1.3", "max_version": "1.2"}`), "", "", ""), "config.value@lines[0].tls.min_version"},
		{"https without host", build("", "", `{"id": "x", "type": "remote", "format": "binary", "url": "https://"}`, ""), "config.value@rule_sets[1].url"},
		{"missing version", `{"scenarios": []}`, "config.value@version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, problems := load(t, tc.doc)
			if !strings.Contains(" "+codes(problems), " "+tc.want) {
				t.Errorf("want %s, got %s", tc.want, codes(problems))
			}
		})
	}
}

func TestLoadNewerVersion(t *testing.T) {
	if _, _, err := Load([]byte(`{"version": 99}`)); err != ErrNewerVersion {
		t.Errorf("err = %v", err)
	}
}

func TestSecretsAreCollectedNotKept(t *testing.T) {
	c, problems := load(t, build(line(""), "", "", ""))
	if len(problems) > 0 {
		t.Fatal(codes(problems))
	}
	if len(c.Secrets) != 1 || c.Secrets[0].Name != "hk" || c.Secrets[0].Path != "lines[0].password" {
		t.Errorf("secrets = %+v", c.Secrets)
	}
}

func TestRegexBudget(t *testing.T) {
	heavy := strings.Repeat(`\\pL{1000}`, 5) // JSON-escaped \pL
	one := build("", "", `{"id": "x", "type": "inline", "rules": [{"domain_regex": ["`+heavy+`"]}]}`, "")
	if _, problems := load(t, one); !strings.Contains(codes(problems), "config.value@rule_sets[1].rules[0].domain_regex") {
		t.Errorf("a heavy regex passed: %s", codes(problems))
	}
	// Many modest patterns add up past the document budget.
	var rules []string
	for i := 0; i < 400; i++ {
		rules = append(rules, `{"domain_regex": ["[a-z]{250}x`+itoa(i)+`"]}`)
	}
	many := build("", "", `{"id": "x", "type": "inline", "rules": [`+strings.Join(rules, ",")+`]}`, "")
	if _, problems := load(t, many); !strings.Contains(codes(problems), "config.value@rule_sets[1].rules[") {
		t.Errorf("the document regex budget did not apply: %s", codes(problems))
	}
}

func TestProblemsAreCapped(t *testing.T) {
	zeros := strings.Repeat("0,", 18999) + "0"
	doc := build("", "", `{"id": "x", "type": "inline", "rules": [{"domain": [`+zeros+`]}]}`, "")
	_, problems := load(t, doc)
	if len(problems) != maxProblems+1 || problems[maxProblems].Code != cli.CodeConfigMore {
		t.Fatalf("got %d problems, last %+v", len(problems), problems[len(problems)-1])
	}
	if !strings.Contains(problems[maxProblems].Message, "18800") {
		t.Errorf("the count of dropped problems is wrong: %s", problems[maxProblems].Message)
	}
}

func TestParseCapsNodes(t *testing.T) {
	doc := "[" + strings.Repeat("0,", maxNodes) + "0]"
	if _, err := Parse([]byte(doc)); err == nil {
		t.Error("a document with too many values parsed")
	}
}

func TestDetourDirectIsRejected(t *testing.T) {
	_, problems := load(t, build(line(`, "detour": "direct"`), "", "", ""))
	if !strings.Contains(codes(problems), "config.reference@lines[0].detour") {
		t.Errorf("detour direct passed: %s", codes(problems))
	}
}

func TestCheckRuleSetSource(t *testing.T) {
	long := `"` + strings.Repeat(`a.example", "`, maxListItems) + `b.example"`
	rules, problems := CheckRuleSetSource([]byte(`{"version": 2, "rules": [{"domain_suffix": [` + long + `]}, {"ip_cidr": ["10.0.0.0/8"], "invert": true}]}`))
	if len(problems) > 0 || len(rules) != 2 {
		t.Fatalf("a long list beyond what a configuration takes: %d rules, %v", len(rules), problems)
	}
	for name, doc := range map[string]string{
		"not an object":  `[]`,
		"no rules":       `{"version": 1}`,
		"no version":     `{"rules": []}`,
		"future version": `{"version": 9, "rules": []}`,
		"unknown key":    `{"version": 1, "rules": [], "extra": 1}`,
		"forbidden":      `{"version": 1, "rules": [{"query_type": ["A"]}]}`,
		"adguard":        `{"version": 1, "rules": [{"adguard_domain": ["||x^"]}]}`,
		"bad cidr":       `{"version": 1, "rules": [{"ip_cidr": ["10.0.0.0/99"]}]}`,
		"bad regex":      `{"version": 1, "rules": [{"domain_regex": ["("]}]}`,
		"syntax":         `{"version": 1, "rules": [}`,
	} {
		if _, problems := CheckRuleSetSource([]byte(doc)); len(problems) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	tooMany := `"` + strings.Repeat(`a", "`, maxRuleSetList) + `b"`
	if _, problems := CheckRuleSetSource([]byte(`{"version": 1, "rules": [{"domain": [` + tooMany + `]}]}`)); len(problems) == 0 {
		t.Error("a list over the cap was accepted")
	}
}

func TestDownloadViaMustNotReachDirectThroughAGroup(t *testing.T) {
	doc := `{"version": 1,
		"lines": [{"id": "hk", "type": "trojan", "server": "hk.example", "server_port": 443, "password": {"secret": "hk"}}],
		"groups": [{"id": "g", "type": "selector", "outbounds": ["hk", "direct"]}],
		"rule_sets": [{"id": "r", "type": "remote", "format": "source", "url": "https://rules.example/r.json", "download_via": "g"}],
		"scenarios": [{"id": "s", "final": "direct"}]}`
	_, problems, _ := Load([]byte(doc))
	if len(problems) != 1 || problems[0].Path != "rule_sets[0].download_via" || problems[0].Code != cli.CodeConfigReference {
		t.Errorf("want one problem on download_via, got %+v", problems)
	}
	if _, problems, _ := Load([]byte(strings.Replace(doc, `["hk", "direct"]`, `["hk"]`, 1))); len(problems) != 0 {
		t.Errorf("a group of proxies only: %+v", problems)
	}
}

func TestRuleSetProblemsDoNotEchoRemoteKeys(t *testing.T) {
	_, problems := CheckRuleSetSource([]byte(`{"version": 1, "rules": [{"domain": ["a"], "token_s3cret": 1, "domain[0]x": 2}]}`))
	if len(problems) == 0 {
		t.Fatal("unknown keys were accepted")
	}
	for _, p := range problems {
		if strings.Contains(p.Path, "s3cret") || strings.Contains(p.Path, "]x") {
			t.Errorf("path echoes a remote key: %q", p.Path)
		}
	}
	if _, problems := CheckRuleSetSource([]byte(`{"version": 1, "rules": []}`)); len(problems) == 0 {
		t.Error("an empty rule set was accepted")
	}
}

func TestDownloadViaThroughADetourIsAllowed(t *testing.T) {
	doc := `{"version": 1,
		"lines": [{"id": "hk", "type": "trojan", "server": "hk.example", "server_port": 443, "password": {"secret": "hk"}, "detour": "g"},
		          {"id": "jp", "type": "trojan", "server": "jp.example", "server_port": 443, "password": {"secret": "jp"}}],
		"groups": [{"id": "g", "type": "selector", "outbounds": ["jp", "direct"]}],
		"rule_sets": [{"id": "r", "type": "remote", "format": "source", "url": "https://rules.example/r.json", "download_via": "hk"}],
		"scenarios": [{"id": "s", "final": "direct"}]}`
	if _, problems, _ := Load([]byte(doc)); len(problems) != 0 {
		t.Errorf("a proxy whose detour may go direct still downloads through the proxy: %+v", problems)
	}
}

func TestUnknownKeyLookingLikeAnIndexIsCut(t *testing.T) {
	for _, doc := range []string{
		`{"version": 1, "rules": [{"domain": ["a"], "domain[123456789]": 1}]}`,
		`{"version": 1, "rules": [{"domain": ["a"], "domain[123456789].x": 1}]}`,
		`{"version": 1, "rules": [{"domain": ["a"]}], "rules[42].token": 1}`,
	} {
		_, problems := CheckRuleSetSource([]byte(doc))
		if len(problems) == 0 {
			t.Errorf("%s: accepted", doc)
		}
		for _, p := range problems {
			if strings.Contains(p.Path, "123456789") || strings.Contains(p.Path, "42") || strings.Contains(p.Path, "token") ||
				strings.Contains(p.Message, "123456789") || strings.Contains(p.Message, "token") {
				t.Errorf("problem echoes a remote key: %+v", p)
			}
		}
	}
}
