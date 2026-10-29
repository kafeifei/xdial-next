package subscription

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func looksLikeClash(data []byte) bool {
	for _, key := range [][]byte{[]byte("proxies:"), []byte("proxy-groups:"), []byte("rules:")} {
		if bytes.HasPrefix(data, key) || bytes.Contains(data, append([]byte("\n"), key...)) {
			return true
		}
	}
	return false
}

func parseClash(data []byte) (*Content, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
		Rules   []any            `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, errors.New("订阅是 Clash 格式，但解析失败")
	}
	c := &Content{Format: "clash"}
	if len(doc.Proxies) > MaxNodes {
		return nil, fmt.Errorf("节点超过 %d 个", MaxNodes)
	}
	for _, p := range doc.Proxies {
		m := clashMap(p)
		typ := m.str("type")
		out, ok := clashOutbound(m)
		if !ok {
			c.skip("node", typ)
			continue
		}
		c.Nodes = append(c.Nodes, Node{Name: clean(m.str("name")), Outbound: marshal(out)})
	}
	if len(doc.Rules) > MaxRules {
		return nil, fmt.Errorf("规则超过 %d 条", MaxRules)
	}
	for _, r := range doc.Rules {
		line, ok := r.(string)
		if !ok || len(line) > maxRuleLine {
			c.skip("rule", "malformed")
			continue
		}
		rule, policy, typ, ok := clashRule(line)
		switch {
		case typ == "MATCH" || typ == "FINAL":
			// The scenario's final takes its place.
		case !ok:
			c.skip("rule", typ)
		default:
			c.Rules = append(c.Rules, Rule{Policy: policy, Rule: marshal(rule)})
		}
	}
	return c, nil
}

// clashMap reads the loosely typed values YAML gives back.
type clashMap map[string]any

func (m clashMap) str(key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func (m clashMap) int(key string) (int, bool) {
	switch v := m[key].(type) {
	case int:
		return v, true
	case string:
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	return 0, false
}

func (m clashMap) bool(key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	case int:
		return v == 1
	}
	return false
}

func (m clashMap) sub(key string) clashMap {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return clashMap{}
}

func (m clashMap) strs(key string) []string {
	switch v := m[key].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// clashOutbound converts one Clash proxy to sing-box outbound options, for
// the types the node allow list admits.
func clashOutbound(m clashMap) (map[string]any, bool) {
	port, ok := m.int("port")
	server := m.str("server")
	if !ok || server == "" {
		return nil, false
	}
	out := map[string]any{"server": server, "server_port": port}
	switch strings.ToLower(m.str("type")) {
	case "ss", "shadowsocks":
		out["type"] = "shadowsocks"
		out["method"] = m.str("cipher")
		out["password"] = m.str("password")
		if plugin, opts, ok := clashPlugin(m); !ok {
			return nil, false
		} else if plugin != "" {
			out["plugin"], out["plugin_opts"] = plugin, opts
		}
		if m.bool("udp-over-tcp") {
			out["udp_over_tcp"] = true
		}
	case "vmess":
		out["type"] = "vmess"
		out["uuid"] = m.str("uuid")
		if aid, ok := m.int("alterId"); ok {
			out["alter_id"] = aid
		}
		if cipher := m.str("cipher"); cipher != "" {
			out["security"] = cipher
		}
	case "vless":
		out["type"] = "vless"
		out["uuid"] = m.str("uuid")
		if flow := m.str("flow"); flow != "" {
			out["flow"] = flow
		}
	case "trojan":
		out["type"] = "trojan"
		out["password"] = m.str("password")
	case "anytls":
		out["type"] = "anytls"
		out["password"] = m.str("password")
		for clash, box := range map[string]string{"idle-session-check-interval": "idle_session_check_interval", "idle-session-timeout": "idle_session_timeout"} {
			if n, ok := m.int(clash); ok {
				out[box] = fmt.Sprintf("%ds", n)
			}
		}
		if n, ok := m.int("min-idle-session"); ok {
			out["min_idle_session"] = n
		}
	default:
		return nil, false
	}
	typ := out["type"].(string)
	// TLS: on by default for trojan and anytls, by "tls: true" otherwise.
	if typ == "trojan" || typ == "anytls" || m.bool("tls") {
		tls := map[string]any{"enabled": true}
		for _, key := range []string{"sni", "servername"} {
			if s := m.str(key); s != "" {
				tls["server_name"] = s
			}
		}
		if m.bool("skip-cert-verify") {
			tls["insecure"] = true
		}
		if alpn := m.strs("alpn"); len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		if fp := m.str("client-fingerprint"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if r := m.sub("reality-opts"); len(r) > 0 {
			tls["reality"] = map[string]any{"enabled": true, "public_key": r.str("public-key"), "short_id": r.str("short-id")}
		}
		out["tls"] = tls
	}
	if typ == "vmess" || typ == "vless" || typ == "trojan" {
		transport, ok := clashTransport(m)
		if !ok {
			return nil, false
		}
		if transport != nil {
			out["transport"] = transport
		}
	}
	if m.bool("tfo") && typ != "anytls" {
		out["tcp_fast_open"] = true
	}
	return out, true
}

// clashTransport converts network and its options; false for a network
// sing-box has no transport for.
func clashTransport(m clashMap) (map[string]any, bool) {
	switch network := strings.ToLower(m.str("network")); network {
	case "", "tcp":
		return nil, true
	case "ws":
		o := m.sub("ws-opts")
		t := map[string]any{"type": "ws"}
		if path := o.str("path"); path != "" {
			t["path"] = path
		}
		if host := o.sub("headers").str("Host"); host != "" {
			t["headers"] = map[string]any{"Host": host}
		}
		if n, ok := o.int("max-early-data"); ok {
			t["max_early_data"] = n
		}
		if name := o.str("early-data-header-name"); name != "" {
			t["early_data_header_name"] = name
		}
		return t, true
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": m.sub("grpc-opts").str("grpc-service-name")}, true
	case "h2", "http":
		key := network + "-opts"
		o := m.sub(key)
		t := map[string]any{"type": "http"}
		if hosts := o.strs("host"); len(hosts) > 0 {
			t["host"] = hosts
		}
		if paths := o.strs("path"); len(paths) > 0 {
			t["path"] = paths[0]
		}
		return t, true
	}
	return nil, false
}

// clashPlugin converts a shadowsocks plugin to sing-box's plugin and
// plugin_opts; false for one it does not support.
func clashPlugin(m clashMap) (string, string, bool) {
	o := m.sub("plugin-opts")
	switch m.str("plugin") {
	case "":
		return "", "", true
	case "obfs":
		opts := "obfs=" + o.str("mode")
		if host := o.str("host"); host != "" {
			opts += ";obfs-host=" + host
		}
		return "obfs-local", opts, true
	case "v2ray-plugin":
		opts := []string{"mode=" + o.str("mode")}
		if o.bool("tls") {
			opts = append(opts, "tls")
		}
		if host := o.str("host"); host != "" {
			opts = append(opts, "host="+host)
		}
		if path := o.str("path"); path != "" {
			opts = append(opts, "path="+path)
		}
		return "v2ray-plugin", strings.Join(opts, ";"), true
	}
	return "", "", false
}

// clashRule converts one Clash rule line, "TYPE,VALUE,POLICY[,options]".
// It returns the rule type even when the rule is not supported.
func clashRule(line string) (rule map[string]any, policy, typ string, ok bool) {
	parts := strings.Split(line, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	typ = strings.ToUpper(parts[0])
	if typ == "MATCH" || typ == "FINAL" {
		return nil, "", typ, false
	}
	if len(parts) < 3 {
		return nil, "", typ, false
	}
	value, policy := parts[1], clean(parts[2])
	if policy == "" || value == "" {
		return nil, "", typ, false
	}
	// no-resolve is dropped: XDial resolves domain destinations before
	// routing either way, ARCHITECTURE.md 3.2.
	switch typ {
	case "DOMAIN":
		return map[string]any{"domain": []string{value}}, policy, typ, true
	case "DOMAIN-SUFFIX":
		return map[string]any{"domain_suffix": []string{value}}, policy, typ, true
	case "DOMAIN-KEYWORD":
		return map[string]any{"domain_keyword": []string{value}}, policy, typ, true
	case "DOMAIN-REGEX":
		return map[string]any{"domain_regex": []string{value}}, policy, typ, true
	case "IP-CIDR", "IP-CIDR6":
		return map[string]any{"ip_cidr": []string{value}}, policy, typ, true
	case "DST-PORT":
		if lo, hi, found := strings.Cut(value, "-"); found {
			return map[string]any{"port_range": []string{lo + ":" + hi}}, policy, typ, true
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			return nil, "", typ, false
		}
		return map[string]any{"port": []int{n}}, policy, typ, true
	case "PROCESS-NAME":
		return map[string]any{"process_name": []string{value}}, policy, typ, true
	case "PROCESS-PATH":
		return map[string]any{"process_path": []string{value}}, policy, typ, true
	case "NETWORK":
		return map[string]any{"network": []string{strings.ToLower(value)}}, policy, typ, true
	}
	return nil, "", typ, false
}
