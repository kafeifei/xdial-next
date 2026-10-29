package subscription

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var linkSchemes = []string{"ss://", "vmess://", "vless://", "trojan://", "anytls://", "ssr://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "socks://", "socks5://", "http://", "https://", "wireguard://"}

// looksLikeLinks is true when the first non-empty line is a share link.
func looksLikeLinks(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), maxRuleLine*4)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		for _, s := range linkSchemes {
			if strings.HasPrefix(strings.ToLower(line), s) {
				return true
			}
		}
		return false
	}
	return false
}

func parseLinks(data []byte) (*Content, error) {
	c := &Content{Format: "links"}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(c.Nodes) >= MaxNodes {
			c.skip("node", "over-limit")
			continue
		}
		scheme, _, _ := strings.Cut(line, "://")
		name, out, ok := parseLink(line)
		if !ok {
			c.skip("node", scheme)
			continue
		}
		c.Nodes = append(c.Nodes, Node{Name: clean(name), Outbound: marshal(out)})
	}
	return c, nil
}

func parseLink(line string) (string, map[string]any, bool) {
	scheme, _, _ := strings.Cut(line, "://")
	switch strings.ToLower(scheme) {
	case "ss":
		return parseSS(line)
	case "vmess":
		return parseVMess(line)
	case "vless", "trojan", "anytls":
		return parseURLLink(strings.ToLower(scheme), line)
	}
	return "", nil, false
}

func hostPort(u *url.URL) (string, int, bool) {
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || host == "" {
		return "", 0, false
	}
	return host, port, true
}

// parseSS reads SIP002, ss://base64(method:password)@host:port, and the
// older ss://base64(method:password@host:port), each with #name.
func parseSS(line string) (string, map[string]any, bool) {
	rest := strings.TrimPrefix(line[len("ss://"):], "")
	body, fragment, _ := strings.Cut(rest, "#")
	name, _ := url.PathUnescape(fragment)
	if !strings.Contains(body, "@") {
		decoded, ok := decodeBase64([]byte(body))
		if !ok {
			return "", nil, false
		}
		body = string(decoded)
	}
	u, err := url.Parse("ss://" + body)
	if err != nil || u.User == nil {
		return "", nil, false
	}
	host, port, ok := hostPort(u)
	if !ok {
		return "", nil, false
	}
	method, password := u.User.Username(), ""
	if p, set := u.User.Password(); set {
		password = p
	} else if decoded, ok := decodeBase64([]byte(method)); ok {
		method, password, _ = strings.Cut(string(decoded), ":")
	}
	out := map[string]any{"type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": password}
	if plugin := u.Query().Get("plugin"); plugin != "" {
		name, opts, _ := strings.Cut(plugin, ";")
		switch name {
		case "obfs-local", "simple-obfs":
			out["plugin"], out["plugin_opts"] = "obfs-local", opts
		case "v2ray-plugin":
			out["plugin"], out["plugin_opts"] = "v2ray-plugin", opts
		default:
			return "", nil, false
		}
	}
	return name, out, true
}

// parseVMess reads the v2rayN form: vmess://base64(JSON).
func parseVMess(line string) (string, map[string]any, bool) {
	decoded, ok := decodeBase64([]byte(line[len("vmess://"):]))
	if !ok {
		return "", nil, false
	}
	var v map[string]any
	if err := json.Unmarshal(decoded, &v); err != nil {
		return "", nil, false
	}
	m := clashMap(v)
	port, ok := m.int("port")
	if !ok {
		if f, isFloat := v["port"].(float64); isFloat {
			port, ok = int(f), true
		}
	}
	server := m.str("add")
	if !ok || server == "" {
		return "", nil, false
	}
	out := map[string]any{"type": "vmess", "server": server, "server_port": port, "uuid": m.str("id")}
	if aid := m.str("aid"); aid != "" {
		if n, err := strconv.Atoi(aid); err == nil {
			out["alter_id"] = n
		}
	}
	if scy := m.str("scy"); scy != "" {
		out["security"] = scy
	}
	withTLS := m.str("tls") == "tls"
	if withTLS {
		tls := map[string]any{"enabled": true}
		if sni := m.str("sni"); sni != "" {
			tls["server_name"] = sni
		} else if host := m.str("host"); host != "" && m.str("net") == "ws" {
			tls["server_name"] = host
		}
		if fp := m.str("fp"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if alpn := m.str("alpn"); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		out["tls"] = tls
	}
	network := m.str("net")
	if network == "tcp" && m.str("type") == "http" {
		// v2rayN's HTTP/1.1 disguise over TCP.
		network = "http/1.1"
	}
	transport, ok := linkTransport(network, m.str("host"), m.str("path"), m.str("path"), withTLS)
	if !ok {
		return "", nil, false
	}
	if transport != nil {
		out["transport"] = transport
	}
	return m.str("ps"), out, true
}

// parseURLLink reads vless://, trojan:// and anytls:// links, whose user is
// the uuid or password and whose query holds the transport and TLS.
func parseURLLink(typ, line string) (string, map[string]any, bool) {
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return "", nil, false
	}
	host, port, ok := hostPort(u)
	if !ok {
		return "", nil, false
	}
	q := u.Query()
	out := map[string]any{"type": typ, "server": host, "server_port": port}
	if typ == "vless" {
		out["uuid"] = u.User.Username()
		if flow := q.Get("flow"); flow != "" {
			out["flow"] = flow
		}
	} else {
		out["password"] = u.User.Username()
	}
	security := q.Get("security")
	if typ != "vless" && security == "" {
		security = "tls"
	}
	withTLS := security == "tls" || security == "reality"
	if withTLS {
		tls := map[string]any{"enabled": true}
		if sni := q.Get("sni"); sni != "" {
			tls["server_name"] = sni
		} else if peer := q.Get("peer"); peer != "" {
			tls["server_name"] = peer
		} else if host := q.Get("host"); host != "" && q.Get("type") == "ws" {
			tls["server_name"] = host
		}
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
			tls["insecure"] = true
		}
		if fp := q.Get("fp"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if alpn := q.Get("alpn"); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		if security == "reality" {
			tls["reality"] = map[string]any{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
		}
		out["tls"] = tls
	} else if security != "" && security != "none" {
		return "", nil, false
	}
	if typ != "anytls" {
		transport, ok := linkTransport(q.Get("type"), q.Get("host"), q.Get("path"), q.Get("serviceName"), withTLS)
		if !ok {
			return "", nil, false
		}
		if transport != nil {
			out["transport"] = transport
		}
	}
	name, _ := url.PathUnescape(u.Fragment)
	if name == "" {
		name = u.Fragment
	}
	return name, out, true
}

// linkTransport converts a share link's network. In these links "http" is
// Xray's, which is HTTP/2 like "h2" and needs TLS; v2rayN's HTTP/1.1
// disguise arrives as "http/1.1" and must go without, as in clashTransport.
func linkTransport(network, host, path, service string, withTLS bool) (map[string]any, bool) {
	switch network {
	case "", "tcp", "raw":
		return nil, true
	case "ws":
		t := map[string]any{"type": "ws"}
		if path != "" {
			t["path"] = path
		}
		if host != "" {
			t["headers"] = map[string]any{"Host": host}
		}
		return t, true
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": service}, true
	case "h2", "http", "http/1.1":
		if withTLS != (network != "http/1.1") {
			return nil, false
		}
		t := map[string]any{"type": "http"}
		if host != "" {
			t["host"] = strings.Split(host, ",")
		}
		if path != "" {
			t["path"] = path
		}
		return t, true
	case "httpupgrade":
		t := map[string]any{"type": "httpupgrade"}
		if host != "" {
			t["host"] = host
		}
		if path != "" {
			t["path"] = path
		}
		return t, true
	}
	return nil, false
}

// parseSingBox reads a sing-box configuration and takes its outbounds of
// the node types; the tag becomes the name.
func parseSingBox(data []byte) (*Content, error) {
	var doc struct {
		Outbounds []map[string]json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, errInvalidSingBox
	}
	c := &Content{Format: "sing-box"}
	for _, o := range doc.Outbounds {
		var typ, tag string
		_ = json.Unmarshal(o["type"], &typ)
		_ = json.Unmarshal(o["tag"], &tag)
		switch typ {
		case "shadowsocks", "vmess", "vless", "trojan", "anytls":
		case "direct", "block", "dns", "selector", "urltest":
			continue
		default:
			c.skip("node", typ)
			continue
		}
		if len(c.Nodes) >= MaxNodes {
			c.skip("node", "over-limit")
			continue
		}
		delete(o, "tag")
		c.Nodes = append(c.Nodes, Node{Name: clean(tag), Outbound: marshal(o)})
	}
	return c, nil
}

type parseError string

func (e parseError) Error() string { return string(e) }

const errInvalidSingBox = parseError("sing-box 格式的订阅解析失败")
