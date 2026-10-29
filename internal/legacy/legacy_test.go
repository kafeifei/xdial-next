package legacy

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// library is a made-up old library with what the import has to handle:
// two profiles, a node, a VPN, a tailscale line, a direct line and one
// that is off; a selector and a urltest group; a rule set group whose
// conditions interleave with another rule set in the scenario's order; an
// app rule; a remote rule set; and Wi-Fi switching.
const library = `{
  "schemaVersion": 3,
  "activeProfileID": "global-configuration",
  "editingProfileID": "p1",
  "activeScenarioID": "s-work",
  "profiles": [
    {"id": "p1", "name": "机场", "profile": {
      "lines": [
        {"id": "n1", "name": "香港 01", "type": "anytls", "anytls_server": "hk.example", "anytls_port": 443, "anytls_password": "pw-1",
         "anytls_sni": "", "anytls_client_fingerprint": "chrome", "anytls_alpn": ["h2"], "anytls_idle_session_check_interval": 30,
         "anytls_idle_session_timeout": 30, "anytls_min_idle_session": 0},
        {"id": "n2", "name": "Japan 02", "type": "anytls", "anytls_server": "jp.example", "anytls_port": 8443, "anytls_password": "pw-2",
         "anytls_sni": "sni.example", "anytls_client_fingerprint": "", "anytls_alpn": [], "native_options": {"tls": {}}},
        {"id": "n3", "name": "坏的", "type": "anytls", "anytls_server": "x.example", "anytls_port": 443, "anytls_password": "pw-3", "tfo": true},
        {"id": "off", "name": "关着的", "type": "anytls", "enabled": false, "anytls_server": "y.example", "anytls_port": 443, "anytls_password": "pw-4"},
        {"id": "d1", "name": "直连", "type": "direct"},
        {"id": "direct", "name": "直连", "type": "direct"}
      ],
      "rule_sets": [
        {"id": "g1", "name": "AI", "type": "group", "conditions": [
          {"id": "c1", "name": "openai", "type": "native", "native_rule": {"domain_suffix": ["openai.com"]}, "no_resolve": true},
          {"id": "c2", "name": "", "type": "native", "native_rule": {"ip_cidr": ["10.0.0.0/8"]}}
        ]},
        {"id": "g2", "name": "国内", "type": "group", "conditions": [
          {"id": "c3", "name": "cn", "type": "native", "native_rule": {"domain_suffix": ["cn"]}}
        ]},
        {"id": "apps", "name": "微信", "type": "application",
         "applications": [{"bundle_identifier": "com.tencent.xinWeChat", "name": "WeChat", "path": "/Applications/WeChat.app"}],
         "processes": ["curl", "Code*", "/usr/bin/ssh", "/opt/tools/"]},
        {"id": "remote", "name": "geoip-cn", "type": "url", "url": "https://example.org/geoip-cn.srs", "format": "auto", "fetch_line_id": "n1", "invert": true}
      ],
      "scenarios": [], "subscriptions": [], "tailscale": {"hostname": ""}
    }},
    {"id": "p2", "name": "公司", "profile": {
      "lines": [
        {"id": "vpn1", "name": "Corp VPN", "type": "vpn", "vpn_server": "vpn.corp.example", "vpn_username": "me", "vpn_password": "vpn-pw", "allow_insecure": true},
        {"id": "ss1", "name": "ss", "type": "shadowsocks", "ss_server": "ss.example", "ss_port": 8388, "ss_method": "aes-256-gcm", "ss_password": "ss-pw", "udp": true, "tfo": true},
        {"id": "ts1", "name": "tailnet", "type": "tailscale", "tailscale_exit_node": "exit"},
        {"id": "direct", "name": "直连", "type": "direct"}
      ],
      "rule_sets": [
        {"id": "corp", "name": "Corp", "type": "manual", "domains": ["corp.example"], "cidrs": []},
        {"id": "via-vpn", "name": "overseas", "type": "url", "url": "https://example.org/overseas.srs", "format": "auto", "fetch_line_id": "vpn1"}
      ],
      "scenarios": [], "subscriptions": [], "tailscale": {"hostname": "my-mac"}
    }}
  ],
  "groups": [
    {"id": "grp-a", "name": "自动", "type": "urltest", "group_members": ["n1", "n2", "off"], "group_url": "https://cp.example/generate_204", "group_interval": "3m"},
    {"id": "grp-s", "name": "Proxy", "type": "selector", "group_members": ["grp-a", "n1", "direct"], "group_default": "n1"}
  ],
  "scenarios": [
    {"id": "s-home", "name": "家", "bindings": [{"rule_set_id": "g2", "line_id": "direct", "subscription_id": "", "condition_ids": []}],
     "default_line_id": "off", "default_subscription_id": "", "match_order": [], "match_ssids": ["Home"]},
    {"id": "s-work", "name": "Work Day", "bindings": [
      {"rule_set_id": "g1", "line_id": "grp-s", "subscription_id": "", "condition_ids": []},
      {"rule_set_id": "g2", "line_id": "direct", "subscription_id": "", "condition_ids": []},
      {"rule_set_id": "corp", "line_id": "vpn1", "subscription_id": "", "condition_ids": []},
      {"rule_set_id": "apps", "line_id": "d1", "subscription_id": "", "condition_ids": []},
      {"rule_set_id": "remote", "line_id": "off", "subscription_id": "", "condition_ids": []}
     ],
     "default_line_id": "grp-a", "default_subscription_id": "", "match_order": ["c2", "c3", "c1"], "match_ssids": []}
  ],
  "groupSources": {}, "scenarioSources": {}
}`

func convert(t *testing.T) (*Result, map[string]any) {
	t.Helper()
	r, err := Convert([]byte(library))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(r.Config, &doc); err != nil {
		t.Fatal(err)
	}
	return r, doc
}

func byID(items any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, item := range items.([]any) {
		m := item.(map[string]any)
		out[m["id"].(string)] = m
	}
	return out
}

func TestConvert(t *testing.T) {
	r, doc := convert(t)
	if len(r.Report.Problems) != 0 {
		t.Fatalf("problems: %+v", r.Report.Problems)
	}
	lines := byID(doc["lines"])
	if ss := lines["ss"]; ss["udp_over_tcp"] != true || ss["tcp_fast_open"] != true {
		t.Errorf("shadowsocks: %v", ss)
	}
	if len(lines) != 5 || lines["line-01"]["name"] != "香港 01" || lines["japan-02"] == nil || lines["corp-vpn"]["type"] != "openconnect" || lines["tailnet"]["hostname"] != "my-mac" {
		t.Errorf("lines: %v", lines)
	}
	hk := lines["line-01"]
	tls := hk["tls"].(map[string]any)
	if hk["password"].(map[string]any)["secret"] != "line-01-password" || tls["server_name"] != "hk.example" ||
		tls["utls"] == nil || hk["idle_session_check_interval"] != "30s" {
		t.Errorf("anytls: %v", hk)
	}
	if vpn := lines["corp-vpn"]; fmt.Sprint(vpn["tls"]) != "map[insecure:true]" {
		t.Errorf("vpn: %v", vpn)
	}
	groups := byID(doc["groups"])
	auto, proxy := groups["group-1"], groups["proxy"]
	if fmt.Sprint(auto["outbounds"]) != "[line-01 japan-02]" || auto["interval"] != "3m" {
		t.Errorf("urltest: %v", auto)
	}
	if fmt.Sprint(proxy["outbounds"]) != "[group-1 line-01 direct]" || proxy["default"] != "line-01" {
		t.Errorf("selector: %v", proxy)
	}
	rules := byID(doc["rule_sets"])
	app := rules["rule-1"]
	if app == nil {
		t.Fatalf("rule sets: %v", rules)
	}
	// One rule per field: the rule set matches when any does, as the old
	// App matched any of an app rule's selectors.
	if fmt.Sprint(app["rules"]) != `[map[process_name:[curl]] map[process_path:[/usr/bin/ssh]] map[process_path_regex:[^/Applications/WeChat\.app/ (^|/)Code[^/]*$ ^/opt/tools/]]]` {
		t.Errorf("app rules: %v", app["rules"])
	}
	remote := rules["geoip-cn"]
	if remote["format"] != "binary" || remote["download_via"] != "line-01" {
		t.Errorf("remote: %v", remote)
	}
	scenarios := doc["scenarios"].([]any)
	if home := scenarios[1].(map[string]any); home["final"] != "direct" {
		t.Errorf("a default line that is off: %v", home)
	}
	work := scenarios[0].(map[string]any)
	if work["name"] != "Work Day" || work["final"] != "group-1" {
		t.Fatalf("the scenario in use goes first: %v", scenarios)
	}
	// The kept order first, c1 after it; then the other bindings. The app
	// rule goes direct; the remote rule set's line is off, so it is skipped.
	var got []string
	for _, rule := range work["rules"].([]any) {
		m := rule.(map[string]any)
		got = append(got, fmt.Sprintf("%s>%s", rules[m["rule_set"].(string)]["name"], m["line"]))
	}
	if strings.Join(got, ",") != "AI>proxy,国内 · cn>direct,AI · openai>proxy,Corp>corp-vpn,微信>direct" {
		t.Errorf("work rules: %v", got)
	}
	if fmt.Sprint(r.Report.Secrets) != "[line-01-password japan-02-password corp-vpn-password ss-password]" {
		t.Errorf("secrets: %v", r.Report.Secrets)
	}
	left := fmt.Sprint(r.Report.LeftOut)
	if rules["overseas"] == nil || rules["overseas"]["download_via"] != nil {
		t.Errorf("a rule set fetched through the VPN: %v", rules["overseas"])
	}
	for _, want := range []string{"坏的", "关着的线路", "no_resolve", "tailnet 的登录状态", "家 按 Wi-Fi 自动切换", "overseas（公司） 的下载线路", "家 的默认线路"} {
		if !strings.Contains(left, want) {
			t.Errorf("left out misses %q: %v", want, left)
		}
	}
	if strings.Contains(string(r.Config), "pw-1") || strings.Contains(string(r.Config), "vpn-pw") {
		t.Error("a secret value is in the configuration")
	}
}

func TestConvertRefusesWhatItCannotCarry(t *testing.T) {
	for name, edit := range map[string][2]string{
		"bundle id only":   {`"path": "/Applications/WeChat.app"`, `"path": ""`},
		"subscription":     {`"line_id": "vpn1", "subscription_id": ""`, `"line_id": "", "subscription_id": "sub"`},
		"native options":   {`"name": "Corp VPN", "type": "vpn"`, `"name": "Corp VPN", "type": "vpn", "native_options": {"x": 1}`},
		"unknown member":   {`"group_members": ["n1", "n2", "off"]`, `"group_members": ["nope"]`},
		"bad match order":  {`"match_order": ["c2", "c3", "c1"]`, `"match_order": ["c2", "c2"]`},
		"bad rule":         {`"native_rule": {"ip_cidr": ["10.0.0.0/8"]}`, `"native_rule": {"ip_cidr": ["not a prefix"]}`},
		"unusable member":  {`"group_members": ["n1", "n2", "off"]`, `"group_members": ["n1", "n3"]`},
		"unusable default": {`"default_line_id": "grp-a"`, `"default_line_id": "n3"`},
		"unusable binding": {`"rule_set_id": "corp", "line_id": "vpn1"`, `"rule_set_id": "corp", "line_id": "n3"`},
	} {
		changed := strings.Replace(library, edit[0], edit[1], 1)
		if changed == library {
			t.Fatalf("%s: the library changed", name)
		}
		r, err := Convert([]byte(changed))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(r.Report.Problems) == 0 {
			t.Errorf("%s: no problem reported", name)
		}
	}
	// An off rule set bound to a line the old App could not use is skipped
	// there before the line matters: it does not stop the import.
	off := strings.Replace(strings.Replace(library, `"rule_set_id": "corp", "line_id": "vpn1"`, `"rule_set_id": "corp", "line_id": "n3"`, 1),
		`"name": "Corp", "type": "manual"`, `"name": "Corp", "type": "manual", "enabled": false`, 1)
	if r, err := Convert([]byte(off)); err != nil || len(r.Report.Problems) != 0 {
		t.Errorf("an off rule set on an unusable line: %v %+v", err, r.Report.Problems)
	}
	if _, err := Convert([]byte(`{"schemaVersion": 2, "profiles": []}`)); err == nil {
		t.Error("an old schema passed")
	}
}

func TestOpen(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	sealed := append(nonce, gcm.Seal(nil, nonce, []byte(library), []byte(aad))...)
	plain, err := Open(sealed, key)
	if err != nil || string(plain) != library {
		t.Fatalf("open: %v", err)
	}
	key[0] ^= 1
	if _, err := Open(sealed, key); err == nil {
		t.Error("a wrong key opened it")
	}
}
