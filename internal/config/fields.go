package config

import (
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"strings"

	"github.com/sagernet/sing-box/transport/sip003"
)

// The classification table, ARCHITECTURE.md 2.3 and 2.4. Every field of an
// allowed type is listed here with its class and value domain; anything not
// listed is rejected. TestClassificationCoversSingBox checks the table against
// sing-box's own option types, so a field added upstream fails the build
// until it is classified here.

const (
	noteInterface = "选择接口、地址或 DNS 的字段由 XDial 统一生成"
	noteLinux     = "只在 Linux 上有意义"
	noteFile      = "会让 root daemon 读本机文件，证书和密钥请写内联内容"
	noteExec      = "会让 root daemon 执行程序"
	noteListen    = "会创建系统接口、绑定端口或改动网关"
	noteExpose    = "会把本机暴露给远端"
	noteRoot      = "要用 root 专属能力"
	noteDeprecate = "上游已弃用"
	noteNotYet    = "第一版不开放"
	noteNoSource  = "语义只在本地没有源码的库里，核实之前不开放"
	noteTag       = "tag 由 XDial 用 id 生成"
)

func idSpec() *Spec {
	return checked(&Spec{shape: shapeString, maxLen: 63}, func(v *Value) string {
		if !validID(v.String) {
			return "id 只能用小写字母、数字和连字符，以字母或数字开头，最长 63 个字符"
		}
		return ""
	})
}

func nameSpec() *Spec { return &Spec{shape: shapeString, maxLen: 128} }

func with(base map[string]*Spec, extra ...map[string]*Spec) map[string]*Spec {
	out := make(map[string]*Spec, len(base))
	for k, v := range base {
		out[k] = v
	}
	for _, m := range extra {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func dialerFields() map[string]*Spec {
	return map[string]*Spec{
		"detour":                  ref("line"),
		"bind_interface":          generated(noteInterface),
		"inet4_bind_address":      generated(noteInterface),
		"inet6_bind_address":      generated(noteInterface),
		"bind_address_no_port":    generated(noteInterface),
		"protect_path":            forbidden("会把每个连接的 socket 交给这个 Unix socket 的监听者"),
		"routing_mark":            forbidden(noteLinux),
		"reuse_addr":              generated(noteInterface),
		"netns":                   forbidden(noteLinux),
		"connect_timeout":         duration(),
		"tcp_fast_open":           boolean(),
		"tcp_multi_path":          boolean(),
		"disable_tcp_keep_alive":  boolean(),
		"tcp_keep_alive":          duration(),
		"tcp_keep_alive_interval": duration(),
		"udp_fragment":            boolean(),
		"domain_resolver":         generated(noteInterface),
		"network_strategy":        generated(noteInterface),
		"network_type":            generated(noteInterface),
		"fallback_network_type":   generated(noteInterface),
		"fallback_delay":          generated(noteInterface),
		"domain_strategy":         forbidden(noteDeprecate),
	}
}

func serverFields() map[string]*Spec {
	return map[string]*Spec{"server": req(host()), "server_port": req(port())}
}

func networkSpec() *Spec { return listOf(enum("tcp", "udp")) }

func pemCertificates() *Spec {
	return checked(&Spec{shape: shapeString, maxLen: 64 << 10}, func(v *Value) string {
		// sing-box panics on certificate text it cannot parse, so it is
		// checked here first, ARCHITECTURE.md 2.2.
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(v.String)) {
			return "不是能解析的 PEM 证书"
		}
		return ""
	})
}

func base64Key(size int) func(string, *Value) string {
	return func(value string, _ *Value) string {
		key, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(key) != size {
			return "应该是 base64 编码的 " + itoa(size) + " 字节密钥"
		}
		return ""
	}
}

func tlsFields() map[string]*Spec {
	pin := checked(&Spec{shape: shapeString, maxLen: 64}, func(v *Value) string {
		if b, err := base64.StdEncoding.DecodeString(v.String); err != nil || len(b) != 32 {
			return "应该是 base64 编码的 SHA-256 摘要"
		}
		return ""
	})
	return map[string]*Spec{
		"enabled":                       boolean(),
		"engine":                        generated("固定为 go"),
		"disable_sni":                   boolean(),
		"server_name":                   host(),
		"insecure":                      boolean(),
		"alpn":                          listOf(str()),
		"min_version":                   enum("1.0", "1.1", "1.2", "1.3"),
		"max_version":                   enum("1.0", "1.1", "1.2", "1.3"),
		"cipher_suites":                 listOf(str()),
		"curve_preferences":             listOf(str()),
		"certificate":                   listOf(pemCertificates()),
		"certificate_path":              forbidden(noteFile),
		"certificate_public_key_sha256": listOf(pin),
		"client_certificate":            forbidden(noteNotYet),
		"client_certificate_path":       forbidden(noteFile),
		"client_key":                    forbidden(noteNotYet),
		"client_key_path":               forbidden(noteFile),
		"fragment":                      boolean(),
		"fragment_fallback_delay":       duration(),
		"record_fragment":               boolean(),
		"spoof":                         forbidden(noteRoot),
		"spoof_method":                  forbidden(noteRoot),
		"kernel_tx":                     forbidden(noteLinux),
		"kernel_rx":                     forbidden(noteLinux),
		"handshake_timeout":             duration(),
		"ech": obj(map[string]*Spec{
			"enabled":                        boolean(),
			"config":                         listOf(str()),
			"config_path":                    forbidden(noteFile),
			"query_server_name":              host(),
			"pq_signature_schemes_enabled":   forbidden(noteDeprecate),
			"dynamic_record_sizing_disabled": forbidden(noteDeprecate),
		}),
		"utls": obj(map[string]*Spec{
			"enabled": boolean(),
			"fingerprint": enum("chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk",
				"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"),
		}),
		"reality": obj(map[string]*Spec{
			"enabled":    boolean(),
			"public_key": str(),
			"short_id":   str(),
		}),
	}
}

func headerName(v *Value) string {
	if v.String == "" || strings.ContainsAny(v.String, " \t\r\n:") {
		return "不是合法的 HTTP 头名"
	}
	return ""
}

func headersSpec() *Spec {
	value := &Spec{Class: MaybeSecret, shape: shapeString, maxLen: 4096, Placeholder: func(*Value) string { return "xdial-placeholder" }}
	return mapOf(headerName, listOf(value))
}

func transportSpec() *Spec {
	typ := enum("http", "ws", "grpc", "httpupgrade")
	return union("", map[string]map[string]*Spec{
		"http": {
			"type": typ, "host": listOf(host()), "path": str(), "method": str(), "headers": headersSpec(),
			"idle_timeout": duration(), "ping_timeout": duration(),
		},
		"ws": {
			"type": typ, "path": str(), "headers": headersSpec(),
			"max_early_data": intRange(0, 1<<16), "early_data_header_name": str(),
		},
		"grpc": {
			"type": typ, "service_name": str(), "idle_timeout": duration(), "ping_timeout": duration(),
			"permit_without_stream": boolean(),
		},
		"httpupgrade": {"type": typ, "host": host(), "path": str(), "headers": headersSpec()},
	})
}

func multiplexSpec() *Spec {
	return obj(map[string]*Spec{
		"enabled":         boolean(),
		"protocol":        enum("h2mux", "smux", "yamux"),
		"max_connections": intRange(0, 1024),
		"min_streams":     intRange(0, 1024),
		"max_streams":     intRange(0, 1024),
		"padding":         boolean(),
		"brutal": obj(map[string]*Spec{
			"enabled":   boolean(),
			"up_mbps":   intRange(0, 100000),
			"down_mbps": intRange(0, 100000),
		}),
	})
}

func password(maxLen int) *Spec {
	return &Spec{
		Class:       Secret,
		Placeholder: func(*Value) string { return "xdial-placeholder" },
		Format: func(value string, _ *Value) string {
			if value == "" || len(value) > maxLen {
				return "不能为空，最多 " + itoa(maxLen) + " 字节"
			}
			return ""
		},
	}
}

// vmess and vless map a value that is not a UUID to a UUIDv5 for Xray
// compatibility, so any non-empty string is a valid id.
func userID() *Spec {
	spec := password(1024)
	spec.Placeholder = func(*Value) string { return "00000000-0000-4000-8000-000000000000" }
	return spec
}

var ssMethods = []string{
	"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
	"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
	"rc4-md5", "chacha20-ietf", "xchacha20",
}

func ss2022KeySize(parent *Value) int {
	method := parent.Get("method")
	if method == nil {
		return 0
	}
	switch method.String {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	}
	return 0
}

func ssPassword() *Spec {
	spec := password(1024)
	spec.Placeholder = func(parent *Value) string {
		if size := ss2022KeySize(parent); size > 0 {
			return base64.StdEncoding.EncodeToString(make([]byte, size))
		}
		return "xdial-placeholder"
	}
	spec.Format = func(value string, parent *Value) string {
		size := ss2022KeySize(parent)
		if size == 0 {
			return password(1024).Format(value, parent)
		}
		// A 2022 client may carry an identity key before the user key.
		for _, part := range strings.Split(value, ":") {
			if msg := base64Key(size)(part, parent); msg != "" {
				return msg
			}
		}
		return ""
	}
	return spec
}

// pluginOptions checks the option string of a SIP003 plugin key by key: the
// string is a second syntax inside one field, ARCHITECTURE.md 2.4.
func pluginOptions(parent *Value) func(*Value) string {
	return func(v *Value) string {
		opts, err := sip003.ParsePluginOptions(v.String)
		if err != nil {
			return "plugin_opts 格式不对"
		}
		plugin := ""
		if p := parent.Get("plugin"); p != nil {
			plugin = p.String
		}
		allowed := map[string][]string{
			"obfs-local":   {"obfs", "obfs-host"},
			"v2ray-plugin": {"tls", "host", "path", "mux", "mode"},
		}[plugin]
		for key, values := range opts {
			if !contains(allowed, key) {
				return "plugin_opts 里的键 " + key + " 不允许（证书路径会让 root daemon 读本机文件；其余键第一版不开放）"
			}
			if key == "mode" && (len(values) != 1 || values[0] != "websocket") {
				return "v2ray-plugin 的 mode 只能是 websocket"
			}
		}
		return ""
	}
}

func shadowsocksFields() map[string]*Spec {
	return map[string]*Spec{
		"method":       req(enum(ssMethods...)),
		"password":     req(ssPassword()),
		"plugin":       enum("obfs-local", "v2ray-plugin"),
		"plugin_opts":  &Spec{shape: shapeString, maxLen: 1024}, // checked against its plugin in checkLine
		"network":      networkSpec(),
		"udp_over_tcp": flag(map[string]*Spec{"enabled": boolean(), "version": intRange(1, 2)}),
		"multiplex":    multiplexSpec(),
	}
}

func lineCommon() map[string]*Spec {
	return map[string]*Spec{"id": req(idSpec()), "name": nameSpec(), "type": req(str()), "tag": forbidden(noteTag)}
}

func proxyLine(extra map[string]*Spec) map[string]*Spec {
	return with(lineCommon(), dialerFields(), serverFields(), extra)
}

func openconnectFields() map[string]*Spec {
	token := obj(map[string]*Spec{
		"mode": enum("totp"),
		"secret": {
			Class:       Secret,
			Placeholder: func(*Value) string { return "JBSWY3DPEHPK3PXP" },
			Format: func(value string, _ *Value) string {
				if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(value, "="))); err != nil || value == "" {
					return "TOTP 种子应该是 base32 编码"
				}
				return ""
			},
		},
		"secret_path": forbidden(noteFile),
		"pin":         forbidden(noteNoSource),
		"password":    forbidden(noteNoSource),
		"device_id":   forbidden(noteNoSource),
		"counter":     forbidden("HOTP 计数器只在内存里，重载后会回退，第一版只支持 TOTP"),
	})
	return with(lineCommon(), dialerFields(), map[string]*Spec{
		"system":                           forbidden(noteListen),
		"udp_timeout":                      duration(),
		"udp_mapping":                      forbidden(noteNotYet),
		"udp_filtering":                    forbidden(noteNotYet),
		"udp_nat_max":                      intRange(0, 1<<20),
		"server":                           req(str()),
		"flavor":                           enum("anyconnect"),
		"username":                         str(),
		"password":                         password(1024),
		"auth_group":                       str(),
		"cookie":                           password(8192),
		"token":                            token,
		"reported_os":                      str(),
		"user_agent":                       str(),
		"version":                          str(),
		"local_hostname":                   str(),
		"mobile":                           forbidden(noteNoSource),
		"csd":                              forbidden(noteExec),
		"hip":                              forbidden(noteExec),
		"tncc":                             forbidden(noteExec),
		"fortinet_host_check":              forbidden(noteNoSource),
		"no_udp":                           boolean(),
		"dtls_local_port":                  forbidden(noteListen),
		"compression_disabled":             boolean(),
		"compression_mode":                 enum("stateless", "all"),
		"ipv6_disabled":                    boolean(),
		"http_keepalive_disabled":          boolean(),
		"xml_post_disabled":                boolean(),
		"external_auth_disabled":           boolean(),
		"password_authentication_disabled": boolean(),
		"tcp_keep_alive_enabled":           boolean(),
		"pfs":                              boolean(),
		"mtu":                              intRange(576, 9000),
		"base_mtu":                         intRange(576, 9000),
		"dpd_interval":                     duration(),
		"reconnect_timeout":                duration(),
		"trojan_interval":                  duration(),
		"queue_length":                     intRange(0, 1<<16),
		"allow_insecure_crypto":            boolean(),
		"tls": obj(map[string]*Spec{
			"insecure":                   boolean(),
			"server_name":                host(),
			"peer_fingerprint":           listOf(str()),
			"system_trust_disabled":      boolean(),
			"certificate_authority":      listOf(pemCertificates()),
			"certificate_authority_path": forbidden(noteFile),
			"client_certificate":         forbidden(noteNotYet),
			"client_certificate_path":    forbidden(noteFile),
			"client_key":                 forbidden(noteNotYet),
			"client_key_path":            forbidden(noteFile),
			"client_key_password":        forbidden(noteNotYet),
			"mca_certificate":            forbidden(noteNotYet),
			"mca_certificate_path":       forbidden(noteFile),
			"mca_key":                    forbidden(noteNotYet),
			"mca_key_path":               forbidden(noteFile),
			"mca_key_password":           forbidden(noteNotYet),
		}),
		"form_entries": forbidden(noteNoSource),
	})
}

func tailscaleFields() map[string]*Spec {
	return with(lineCommon(), dialerFields(), map[string]*Spec{
		"state_directory":               generated("登录状态放在 root 专属目录里"),
		"auth_key":                      generated("只在 xdial tailscale login 时从 stdin 读一次，不保存"),
		"control_url":                   httpsURL(),
		"ephemeral":                     boolean(),
		"hostname":                      &Spec{shape: shapeString, maxLen: 63},
		"accept_routes":                 boolean(),
		"exit_node":                     str(),
		"exit_node_allow_lan_access":    boolean(),
		"advertise_routes":              forbidden(noteExpose),
		"advertise_exit_node":           forbidden(noteExpose),
		"advertise_tags":                forbidden(noteExpose),
		"relay_server_port":             forbidden(noteListen),
		"relay_server_static_endpoints": forbidden(noteListen),
		"system_interface":              forbidden(noteListen),
		"system_interface_name":         forbidden(noteListen),
		"system_interface_mtu":          forbidden(noteListen),
		"udp_timeout":                   duration(),
		"ssh_server":                    forbidden(noteExpose),
	})
}

// lineSpec is the allow list for lines, ARCHITECTURE.md 2.3.
func lineSpec() *Spec {
	tls := map[string]*Spec{"tls": obj(tlsFields())}
	return union("", map[string]map[string]*Spec{
		"shadowsocks": proxyLine(shadowsocksFields()),
		"vmess": proxyLine(with(tls, map[string]*Spec{
			"uuid":                 req(userID()),
			"security":             enum("auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"),
			"alter_id":             intRange(0, 65535),
			"global_padding":       boolean(),
			"authenticated_length": boolean(),
			"network":              networkSpec(),
			"packet_encoding":      enum("packetaddr", "xudp"),
			"multiplex":            multiplexSpec(),
			"transport":            transportSpec(),
		})),
		"vless": proxyLine(with(tls, map[string]*Spec{
			"uuid":            req(userID()),
			"flow":            enum("xtls-rprx-vision"),
			"network":         networkSpec(),
			"multiplex":       multiplexSpec(),
			"transport":       transportSpec(),
			"packet_encoding": enum("packetaddr", "xudp"),
		})),
		"trojan": proxyLine(with(tls, map[string]*Spec{
			"password":  req(password(1024)),
			"network":   networkSpec(),
			"multiplex": multiplexSpec(),
			"transport": transportSpec(),
		})),
		"anytls": proxyLine(with(tls, map[string]*Spec{
			"password":                    req(password(1024)),
			"idle_session_check_interval": duration(),
			"idle_session_timeout":        duration(),
			"min_idle_session":            intRange(0, 1024),
		})),
		"openconnect": openconnectFields(),
		"tailscale":   tailscaleFields(),
	})
}

// endpointTypes are the line types sing-box registers as endpoints.
var endpointTypes = map[string]bool{"openconnect": true, "tailscale": true}

func groupSpec() *Spec {
	common := map[string]*Spec{"id": req(idSpec()), "name": nameSpec(), "type": req(str()), "tag": forbidden(noteTag)}
	members := &Spec{shape: shapeArray, elem: ref("line"), maxItems: 1024}
	return union("", map[string]map[string]*Spec{
		"selector": with(common, map[string]*Spec{
			"outbounds":                   req(members),
			"default":                     ref("line"),
			"interrupt_exist_connections": boolean(),
		}),
		"urltest": with(common, map[string]*Spec{
			"outbounds":                   req(members),
			"url":                         checked(&Spec{shape: shapeString, maxLen: 2048}, httpOrHTTPS),
			"interval":                    duration(),
			"tolerance":                   intRange(0, 10000),
			"idle_timeout":                duration(),
			"interrupt_exist_connections": boolean(),
		}),
	})
}

func httpOrHTTPS(v *Value) string {
	if !strings.HasPrefix(v.String, "https://") && !strings.HasPrefix(v.String, "http://") {
		return "应该是 http 或 https 地址"
	}
	return ""
}

// Limits on matching content, which the root daemon compiles into matchers.
const (
	maxRulesPerSet = 20000
	maxListItems   = 20000
)

func headlessRuleSpec(depth int) *Spec {
	bigList := func(elem *Spec) *Spec {
		return &Spec{shape: shapeListable, elem: elem, maxItems: maxListItems}
	}
	plain := map[string]*Spec{
		"type":                      enum("default"),
		"domain":                    bigList(str()),
		"domain_suffix":             bigList(str()),
		"domain_keyword":            bigList(str()),
		"domain_regex":              &Spec{shape: shapeListable, elem: regex(), maxItems: 256},
		"ip_cidr":                   bigList(cidr()),
		"port":                      bigList(intRange(0, 65535)),
		"port_range":                bigList(portRange()),
		"source_port":               bigList(intRange(0, 65535)),
		"source_port_range":         bigList(portRange()),
		"process_name":              bigList(str()),
		"process_path":              bigList(str()),
		"process_path_regex":        &Spec{shape: shapeListable, elem: regex(), maxItems: 256},
		"network":                   listOf(enum("tcp", "udp", "icmp")),
		"invert":                    boolean(),
		"source_ip_cidr":            forbidden(noteNotYet),
		"query_type":                forbidden(noteNotYet),
		"package_name":              forbidden("只用于 Android"),
		"package_name_regex":        forbidden("只用于 Android"),
		"network_type":              forbidden(noteNotYet),
		"network_is_expensive":      forbidden(noteNotYet),
		"network_is_constrained":    forbidden(noteNotYet),
		"wifi_ssid":                 forbidden(noteNotYet),
		"wifi_bssid":                forbidden(noteNotYet),
		"network_interface_address": forbidden(noteNotYet),
		"default_interface_address": forbidden(noteNotYet),
	}
	variants := map[string]map[string]*Spec{"default": plain}
	if depth < 4 {
		variants["logical"] = map[string]*Spec{
			"type":   enum("logical"),
			"mode":   enum("and", "or"),
			"rules":  &Spec{shape: shapeArray, elem: headlessRuleSpec(depth + 1), maxItems: 64},
			"invert": boolean(),
		}
	}
	return union("default", variants)
}

func ruleSetSpec() *Spec {
	common := map[string]*Spec{"id": req(idSpec()), "name": nameSpec(), "type": req(str()), "tag": forbidden(noteTag)}
	return union("", map[string]map[string]*Spec{
		"inline": with(common, map[string]*Spec{
			"format": forbidden("inline 规则集没有 format"),
			"rules":  req(&Spec{shape: shapeArray, elem: headlessRuleSpec(0), maxItems: maxRulesPerSet}),
		}),
		"remote": with(common, map[string]*Spec{
			"format":          req(enum("source", "binary")),
			"url":             req(remoteURL()),
			"download_via":    ref("line"),
			"update_interval": duration(),
			"initial_path":    forbidden(noteFile),
			"http_client":     generated("规则集由 daemon 自己下载"),
			"download_detour": forbidden(noteDeprecate),
		}),
	})
}

func remoteURL() *Spec {
	return &Spec{
		Class:       MaybeSecret,
		shape:       shapeString,
		maxLen:      2048,
		check:       func(v *Value) string { return httpsURL().check(v) },
		Placeholder: func(*Value) string { return "https://xdial.invalid/rule-set" },
		Format: func(value string, _ *Value) string {
			if !strings.HasPrefix(value, "https://") {
				return "只能是 https 地址"
			}
			return ""
		},
	}
}

func subscriptionSpec() *Spec {
	url := remoteURL()
	url.Class = Secret
	return obj(map[string]*Spec{
		"id":           req(idSpec()),
		"name":         nameSpec(),
		"url":          req(url),
		"download_via": ref("line"),
	})
}

func scenarioSpec() *Spec {
	rule := obj(map[string]*Spec{
		"rule_set": req(ref("rule_set")),
		"line":     req(ref("target")),
		"invert":   boolean(),
	})
	return obj(map[string]*Spec{
		"id":    req(idSpec()),
		"name":  nameSpec(),
		"rules": &Spec{shape: shapeArray, elem: rule, maxItems: 1024},
		"final": req(ref("target")),
	})
}

func mixedSpec() *Spec {
	return obj(map[string]*Spec{
		"port":     req(intRange(1024, 65535)),
		"username": req(checked(&Spec{shape: shapeString, maxLen: 255}, nonEmpty)),
		"password": req(password(255)),
	})
}

func nonEmpty(v *Value) string {
	if v.String == "" {
		return "不能为空"
	}
	return ""
}

// documentSpec is the whole configuration file, ARCHITECTURE.md 1.3.
func documentSpec() map[string]*Spec {
	return map[string]*Spec{
		"version":       req(intRange(1, 1<<20)),
		"mixed":         mixedSpec(),
		"lines":         &Spec{shape: shapeArray, elem: lineSpec(), maxItems: 1024},
		"groups":        &Spec{shape: shapeArray, elem: groupSpec(), maxItems: 256},
		"rule_sets":     &Spec{shape: shapeArray, elem: ruleSetSpec(), maxItems: 256},
		"scenarios":     &Spec{shape: shapeArray, elem: scenarioSpec(), maxItems: 64},
		"subscriptions": &Spec{shape: shapeArray, elem: subscriptionSpec(), maxItems: 64},
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
