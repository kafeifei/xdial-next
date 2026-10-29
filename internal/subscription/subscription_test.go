package subscription

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kafeifei/xdial-next/internal/config"
)

const clashDoc = `
mixed-port: 7890
proxies:
  - {name: "香港 01", type: ss, server: hk.example.com, port: 8388, cipher: aes-128-gcm, password: "p1"}
  - name: "香港 01"
    type: ss
    server: hk2.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: p2
    plugin: obfs
    plugin-opts: {mode: http, host: bing.com}
  - {name: "日本 vmess", type: vmess, server: jp.example.com, port: 443, uuid: 1386f85e-657b-4d6e-9d56-78badb75e1fd, alterId: 0, cipher: auto, tls: true, servername: jp.example.com, network: ws, ws-opts: {path: /v, headers: {Host: jp.example.com}}}
  - {name: "美国 vless", type: vless, server: us.example.com, port: 443, uuid: 1386f85e-657b-4d6e-9d56-78badb75e1fd, flow: xtls-rprx-vision, tls: true, servername: www.apple.com, client-fingerprint: chrome, reality-opts: {public-key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", short-id: "0123abcd"}}
  - {name: "新加坡 trojan", type: trojan, server: sg.example.com, port: 443, password: p3, sni: sg.example.com, network: grpc, grpc-opts: {grpc-service-name: svc}}
  - {name: "台湾 anytls", type: anytls, server: tw.example.com, port: 443, password: p4, client-fingerprint: chrome}
  - {name: "hy2", type: hysteria2, server: h.example.com, port: 443, password: p5}
  - {name: "info: 剩余流量 10G", type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: "🚀 节点选择", type: select, proxies: ["香港 01", DIRECT]}
rules:
  - DOMAIN-SUFFIX,google.com,🚀 节点选择
  - DOMAIN,a.example.com,DIRECT
  - DOMAIN-KEYWORD,ads,REJECT
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - DST-PORT,8000-9000,🚀 节点选择
  - GEOIP,CN,DIRECT
  - RULE-SET,custom,REJECT
  - MATCH,🚀 节点选择
`

func checkNodes(t *testing.T, c *Content) {
	t.Helper()
	for _, n := range c.Nodes {
		v, err := config.Parse(n.Outbound)
		if err != nil {
			t.Fatalf("%s: %v", n.Name, err)
		}
		if problems := config.CheckNode(v); len(problems) > 0 {
			t.Errorf("node %q fails the node checks: %+v\n%s", n.Name, problems, n.Outbound)
		}
	}
}

func TestClash(t *testing.T) {
	c, err := Parse([]byte(clashDoc))
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != "clash" {
		t.Errorf("format %q", c.Format)
	}
	var names []string
	for _, n := range c.Nodes {
		names = append(names, n.Name)
	}
	want := "香港 01|香港 01 (2)|日本 vmess|美国 vless|新加坡 trojan|台湾 anytls|info: 剩余流量 10G"
	if strings.Join(names, "|") != want {
		t.Errorf("nodes: %s", strings.Join(names, "|"))
	}
	checkNodes(t, c)
	if c.Unsupported["node:hysteria2"] != 1 || c.Unsupported["rule:geoip"] != 1 || c.Unsupported["rule:rule-set"] != 1 {
		t.Errorf("unsupported: %v", c.Unsupported)
	}
	var policies []string
	for _, r := range c.Rules {
		policies = append(policies, r.Policy)
	}
	if strings.Join(policies, ",") != "🚀 节点选择,DIRECT,REJECT,DIRECT,🚀 节点选择" {
		t.Errorf("rule policies: %v", policies)
	}
	var rule map[string]any
	_ = json.Unmarshal(c.Rules[4].Rule, &rule)
	if rule["port_range"].([]any)[0] != "8000:9000" {
		t.Errorf("port range: %v", rule)
	}
}

func TestLinks(t *testing.T) {
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"vm","add":"vm.example.com","port":"443","id":"1386f85e-657b-4d6e-9d56-78badb75e1fd","aid":"0","scy":"auto","net":"ws","host":"vm.example.com","path":"/ws","tls":"tls","sni":"vm.example.com"}`))
	links := strings.Join([]string{
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pass")) + "@ss.example.com:8388#SS%20%E9%A6%99%E6%B8%AF",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@old.example.com:8388")) + "#legacy",
		"vmess://" + vmess,
		"vless://1386f85e-657b-4d6e-9d56-78badb75e1fd@vl.example.com:443?security=reality&sni=www.apple.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=ab&flow=xtls-rprx-vision&type=tcp#vless",
		"trojan://pw@tr.example.com:443?sni=tr.example.com&type=ws&path=%2Ft&host=tr.example.com#trojan",
		"anytls://pw@at.example.com:443?sni=at.example.com#anytls",
		"hysteria2://pw@h.example.com:443#hy2",
		"",
	}, "\n")
	for name, data := range map[string]string{"plain": links, "base64": base64.StdEncoding.EncodeToString([]byte(links))} {
		c, err := Parse([]byte(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(c.Nodes) != 6 || c.Unsupported["node:hysteria2"] != 1 {
			t.Errorf("%s: %d nodes, unsupported %v", name, len(c.Nodes), c.Unsupported)
		}
		if c.Nodes[0].Name != "SS 香港" {
			t.Errorf("%s: name %q", name, c.Nodes[0].Name)
		}
		checkNodes(t, c)
	}
}

func TestSingBox(t *testing.T) {
	c, err := Parse([]byte(`{"outbounds": [
		{"type": "selector", "tag": "proxy", "outbounds": ["a"]},
		{"type": "trojan", "tag": "a", "server": "a.example.com", "server_port": 443, "password": "p", "tls": {"enabled": true}},
		{"type": "direct", "tag": "direct"},
		{"type": "wireguard", "tag": "wg"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Nodes) != 1 || c.Nodes[0].Name != "a" || c.Unsupported["node:wireguard"] != 1 {
		t.Errorf("%+v", c)
	}
	checkNodes(t, c)
}

func TestNodesMustPassTheNodeChecks(t *testing.T) {
	for name, outbound := range map[string]string{
		"detour":      `{"type": "trojan", "server": "a.example", "server_port": 443, "password": "p", "detour": "x"}`,
		"secret ref":  `{"type": "trojan", "server": "a.example", "server_port": 443, "password": {"secret": "hk"}}`,
		"endpoint":    `{"type": "tailscale"}`,
		"interface":   `{"type": "trojan", "server": "a.example", "server_port": 443, "password": "p", "bind_interface": "en0"}`,
		"bad method":  `{"type": "shadowsocks", "server": "a.example", "server_port": 443, "method": "rc4", "password": "p"}`,
		"empty pass":  `{"type": "trojan", "server": "a.example", "server_port": 443, "password": ""}`,
		"unknown key": `{"type": "trojan", "server": "a.example", "server_port": 443, "password": "p", "x": 1}`,
	} {
		v, err := config.Parse([]byte(outbound))
		if err != nil {
			t.Fatal(err)
		}
		if problems := config.CheckNode(v); len(problems) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for name, data := range map[string]string{
		"empty":     "  \n",
		"unknown":   "hello world",
		"no nodes":  "proxies: []\nrules:\n  - MATCH,DIRECT\n",
		"bad yaml":  "proxies: [\n",
		"bad json":  "{",
		"only hy2":  "hysteria2://pw@h.example.com:443#hy2\n",
		"too large": strings.Repeat("x", MaxSize+1),
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNamesAreCleaned(t *testing.T) {
	c, err := Parse([]byte("proxies:\n  - {name: \"a\\u001b[31mb\\u202ec\", type: trojan, server: a.example, port: 443, password: p}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Nodes[0].Name != "a [31mb c" {
		t.Errorf("name %q", c.Nodes[0].Name)
	}
}
