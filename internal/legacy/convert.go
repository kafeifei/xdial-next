package legacy

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/kafeifei/xdial-next/internal/config"
)

// Result is a converted library: a configuration, the secrets it uses and
// what the conversion did.
type Result struct {
	// Config is the configuration, which refers to Secrets by name.
	Config  []byte
	Secrets []Secret
	Report  Report
}

// Secret is a credential the configuration refers to.
type Secret struct {
	Name, Value string
}

// Report says what an import carries over and what it does not. Problems
// are what cannot be carried over: an import refuses while there are any.
// LeftOut is what the new version does without, by design.
type Report struct {
	Profiles  int      `json:"profiles"`
	Lines     int      `json:"lines"`
	Groups    int      `json:"groups"`
	RuleSets  int      `json:"rule_sets"`
	Scenarios int      `json:"scenarios"`
	Secrets   []string `json:"secrets"`
	LeftOut   []Item   `json:"left_out"`
	Problems  []Item   `json:"problems"`
}

// Item is one thing a report names.
type Item struct {
	What string `json:"what"`
	Why  string `json:"why"`
}

// Convert turns a decrypted library into a configuration. Old ids become
// ids the configuration allows; names stay. The scenario in use goes first,
// so it is the one a plain connect uses.
func Convert(plain []byte) (*Result, error) {
	var lib Library
	if err := json.Unmarshal(plain, &lib); err != nil {
		return nil, fmt.Errorf("旧配置库读不出来：%w", err)
	}
	if lib.SchemaVersion != 3 {
		return nil, fmt.Errorf("旧配置库是第 %d 版，只认第 3 版：先用旧版 XDial 打开一次，让它升级", lib.SchemaVersion)
	}
	c := &converter{lib: &lib, used: map[string]bool{config.Direct: true, config.Block: true},
		lineIDs: map[string]string{}, lineTypes: map[string]string{}, conditions: map[string]*condition{}, members: map[string][]string{}}
	c.report.Profiles = len(lib.Profiles)
	c.convertLines()
	c.convertGroups()
	c.convertRuleSets()
	c.convertScenarios()
	doc := map[string]any{"version": config.CurrentVersion, "scenarios": c.scenarios}
	if len(c.lines) > 0 {
		doc["lines"] = c.lines
	}
	if len(c.groups) > 0 {
		doc["groups"] = c.groups
	}
	if len(c.ruleSets) > 0 {
		doc["rule_sets"] = c.ruleSets
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	// The same checks an apply runs: what does not pass is a problem of
	// the conversion, named by where it is in the result.
	if _, problems, err := config.Load(out); err != nil {
		c.problem("转出的配置", err.Error())
	} else {
		for _, p := range problems {
			c.problem("转出的配置 "+p.Path, p.Message)
		}
	}
	c.report.Lines, c.report.Groups, c.report.RuleSets, c.report.Scenarios = len(c.lines), len(c.groups), len(c.ruleSets), len(c.scenarios)
	for _, s := range c.secrets {
		c.report.Secrets = append(c.report.Secrets, s.Name)
	}
	if c.report.Secrets == nil {
		c.report.Secrets = []string{}
	}
	if c.report.LeftOut == nil {
		c.report.LeftOut = []Item{}
	}
	if c.report.Problems == nil {
		c.report.Problems = []Item{}
	}
	return &Result{Config: out, Secrets: c.secrets, Report: c.report}, nil
}

type converter struct {
	lib     *Library
	report  Report
	secrets []Secret
	used    map[string]bool
	// lineIDs maps old line and group ids to new ones: "direct" for
	// direct lines, "" for lines that are off or left out.
	lineIDs map[string]string
	// lineTypes are the types of the new lines, by new id.
	lineTypes map[string]string
	// conditions are the old rule sets that match, by old id: a group's
	// conditions and the rule sets that are not groups.
	conditions map[string]*condition
	// members are the conditions of each old rule set, by its old id.
	members                          map[string][]string
	lines, groups, ruleSets          []any
	scenarios                        []any
	noResolve                        int
	ruleSetsOff, linesOff, groupsOff []string
}

// condition is an old rule set that matches, and the new rule set it
// became; "" when it was off or matched nothing.
type condition struct {
	rule RuleSet
	id   string
}

func (c *converter) problem(what, why string) {
	c.report.Problems = append(c.report.Problems, Item{what, why})
}

func (c *converter) leftOut(what, why string) {
	c.report.LeftOut = append(c.report.LeftOut, Item{what, why})
}

// unusable marks an old line that is on but that the old App could not
// use either: what refers to it did not connect there, so it cannot here.
const unusable = "\x00unusable"

var notID = regexp.MustCompile(`[^a-z0-9]+`)

// newID makes an id the configuration allows from name, else from kind,
// unique among all ids made.
func (c *converter) newID(kind, name string) string {
	base := strings.Trim(notID.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(base) > 40 {
		base = strings.TrimRight(base[:40], "-")
	}
	// A name with no letter to read, such as 香港 01, keeps its digits
	// after the kind: line-01.
	if strings.IndexFunc(base, func(r rune) bool { return r >= 'a' && r <= 'z' }) < 0 {
		base = strings.Trim(kind+"-"+base, "-")
	}
	id, n := base, 2
	if base == kind {
		id = kind + "-1"
	}
	for ; c.used[id]; n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	c.used[id] = true
	return id
}

// secret keeps value as a secret of the line with id and returns the
// reference to it.
func (c *converter) secret(id, what, value string) map[string]any {
	name := id + "-" + what
	c.secrets = append(c.secrets, Secret{name, value})
	return map[string]any{"secret": name}
}

func (c *converter) convertLines() {
	for _, record := range c.lib.Profiles {
		for _, l := range record.Profile.Lines {
			label := fmt.Sprintf("线路 %s（%s）", l.Name, record.Name)
			// Every profile has its own direct line, under the same id.
			if to, dup := c.lineIDs[l.ID]; dup && (l.Type != "direct" || to != config.Direct) {
				c.problem(label, "id 和别的线路重复")
				continue
			}
			c.lineIDs[l.ID] = ""
			if l.isGroup() {
				c.problem(label, "配置里的线路组不该在 Profile 里，这份库可能还没升到第 3 版")
				continue
			}
			if !l.enabled() {
				c.linesOff = append(c.linesOff, l.Name)
				continue
			}
			if l.Type == "direct" {
				c.lineIDs[l.ID] = config.Direct
				continue
			}
			if !emptyJSON(l.NativeOptions) {
				c.problem(label, "带额外的 sing-box 选项（native_options），还转不了")
				continue
			}
			out, why := c.line(l, record)
			if why != "" {
				c.lineIDs[l.ID] = unusable
				c.leftOut(label, why+"；用到它的场景和组导入不了")
				continue
			}
			c.lineIDs[l.ID] = out["id"].(string)
			c.lineTypes[out["id"].(string)] = out["type"].(string)
			c.lines = append(c.lines, out)
		}
	}
	if len(c.linesOff) > 0 {
		c.leftOut(fmt.Sprintf("%d 条关着的线路", len(c.linesOff)), "旧版里关着，不导入；用到它们的规则也跳过，和旧版一样")
	}
}

// line converts one line, or says why it is left out: what the old App
// could not use either.
func (c *converter) line(l Line, record Record) (out map[string]any, why string) {
	id := c.newID("line", l.Name)
	defer func() {
		if why != "" {
			delete(c.used, id)
		}
	}()
	out = map[string]any{"id": id, "name": l.Name}
	tls := func(serverName string) map[string]any {
		t := map[string]any{"enabled": true}
		if serverName != "" {
			t["server_name"] = serverName
		}
		if l.Insecure {
			t["insecure"] = true
		}
		return t
	}
	switch l.Type {
	case "anytls":
		// sing-box refuses AnyTLS over TCP Fast Open, and so did the old App.
		if l.TFO || l.AnyTLSServer == "" || l.AnyTLSPort <= 0 || l.AnyTLSPassword == "" {
			return nil, "缺服务器、端口或密码，或者开着 TFO：旧版也用不了它"
		}
		serverName := l.AnyTLSSNI
		if serverName == "" {
			serverName = l.AnyTLSServer
		}
		t := tls(serverName)
		if len(l.AnyTLSALPN) > 0 {
			t["alpn"] = l.AnyTLSALPN
		}
		if l.AnyTLSClientFingerprint != "" {
			t["utls"] = map[string]any{"enabled": true, "fingerprint": l.AnyTLSClientFingerprint}
		}
		out["type"], out["server"], out["server_port"], out["tls"] = "anytls", l.AnyTLSServer, l.AnyTLSPort, t
		out["password"] = c.secret(id, "password", l.AnyTLSPassword)
		if l.AnyTLSIdleCheck > 0 {
			out["idle_session_check_interval"] = fmt.Sprintf("%ds", l.AnyTLSIdleCheck)
		}
		if l.AnyTLSIdleTimeout > 0 {
			out["idle_session_timeout"] = fmt.Sprintf("%ds", l.AnyTLSIdleTimeout)
		}
		if l.AnyTLSMinIdle > 0 {
			out["min_idle_session"] = l.AnyTLSMinIdle
		}
	case "trojan":
		if l.TrojanServer == "" || l.TrojanPort <= 0 || l.TrojanPassword == "" {
			return nil, "缺服务器、端口或密码：旧版也用不了它"
		}
		out["type"], out["server"], out["server_port"], out["tls"] = "trojan", l.TrojanServer, l.TrojanPort, tls(l.TrojanSNI)
		out["password"] = c.secret(id, "password", l.TrojanPassword)
		transport(out, l)
	case "shadowsocks":
		if l.SSServer == "" || l.SSPort <= 0 || l.SSMethod == "" || l.SSPassword == "" {
			return nil, "缺服务器、端口、加密方式或密码：旧版也用不了它"
		}
		out["type"], out["server"], out["server_port"], out["method"] = "shadowsocks", l.SSServer, l.SSPort, l.SSMethod
		out["password"] = c.secret(id, "password", l.SSPassword)
		transport(out, l)
	case "vmess":
		if l.VMessServer == "" || l.VMessPort <= 0 || l.VMessUUID == "" {
			return nil, "缺服务器、端口或 UUID：旧版也用不了它"
		}
		out["type"], out["server"], out["server_port"] = "vmess", l.VMessServer, l.VMessPort
		out["uuid"] = c.secret(id, "uuid", l.VMessUUID)
		if l.VMessAltID > 0 {
			out["alter_id"] = l.VMessAltID
		}
		transport(out, l)
	case "vpn":
		if l.VPNServer == "" {
			return nil, "没有服务器：旧版也用不了它"
		}
		out["type"], out["flavor"], out["server"] = "openconnect", "anyconnect", l.VPNServer
		if l.VPNUsername != "" {
			out["username"] = l.VPNUsername
		}
		if l.VPNPassword != "" {
			out["password"] = c.secret(id, "password", l.VPNPassword)
		}
		if l.Insecure {
			out["tls"] = map[string]any{"insecure": true}
		}
	case "tailscale":
		out["type"] = "tailscale"
		if h := record.Profile.Tailscale.Hostname; h != "" && len(h) <= 63 {
			out["hostname"] = h
		}
		if l.TailscaleExitNode != "" {
			out["exit_node"] = l.TailscaleExitNode
		}
		c.leftOut("tailscale 线路 "+l.Name+" 的登录状态", "不迁移：导入后用 xdial tailscale login 重新登录")
	default:
		return nil, "线路类型 " + l.Type + " 新版不支持"
	}
	return out, ""
}

// transport carries the old App's dialing switches over, as its
// applyTransport did for Trojan, Shadowsocks and VMess.
func transport(out map[string]any, l Line) {
	if l.TFO {
		out["tcp_fast_open"] = true
	}
	if l.UDP {
		out["udp_over_tcp"] = true
	}
}

func (c *converter) convertGroups() {
	// Ids first: groups may name groups.
	for _, g := range c.lib.Groups {
		if !g.isGroup() || !g.enabled() {
			c.lineIDs[g.ID] = ""
			if !g.enabled() {
				c.groupsOff = append(c.groupsOff, g.Name)
			}
			continue
		}
		c.lineIDs[g.ID] = c.newID("group", g.Name)
	}
	for _, g := range c.lib.Groups {
		id := c.lineIDs[g.ID]
		if id == "" {
			continue
		}
		label := "线路组 " + g.Name
		var members []any
		for _, m := range g.GroupMembers {
			switch to, known := c.lineIDs[m]; {
			case !known && m == config.Direct:
				members = append(members, config.Direct)
			case !known:
				c.problem(label, "成员 "+m+" 不在旧库里")
			case to == unusable:
				c.problem(label, "有成员旧版也用不了")
			case to != "":
				members = append(members, to)
			}
		}
		if len(members) == 0 {
			c.problem(label, "没有能导入的成员")
			continue
		}
		out := map[string]any{"id": id, "name": g.Name, "type": g.Type, "outbounds": members}
		if g.Type == "selector" && g.GroupDefault != "" {
			if to := c.lineIDs[g.GroupDefault]; to != "" {
				out["default"] = to
			} else if g.GroupDefault == config.Direct {
				out["default"] = config.Direct
			}
		}
		if g.Type == "urltest" {
			if g.GroupURL != "" {
				out["url"] = g.GroupURL
			}
			if g.GroupInterval != "" {
				out["interval"] = g.GroupInterval
			}
		}
		c.groups = append(c.groups, out)
	}
	if len(c.groupsOff) > 0 {
		c.leftOut(fmt.Sprintf("%d 个关着的线路组", len(c.groupsOff)), "旧版里关着，不导入")
	}
}

func (c *converter) convertRuleSets() {
	for _, record := range c.lib.Profiles {
		for _, r := range record.Profile.RuleSets {
			if r.Type != "group" {
				c.members[r.ID] = []string{r.ID}
				c.addCondition(r, r.enabled(), record.Name)
				continue
			}
			for _, cond := range r.Conditions {
				c.members[r.ID] = append(c.members[r.ID], cond.ID)
				// A condition's name says little without its group's.
				if cond.Name == "" || cond.Name == r.Name {
					cond.Name = r.Name
				} else {
					cond.Name = r.Name + " · " + cond.Name
				}
				c.addCondition(cond, r.enabled() && cond.enabled(), record.Name)
			}
		}
	}
	if len(c.ruleSetsOff) > 0 {
		c.leftOut(fmt.Sprintf("%d 条关着的规则", len(c.ruleSetsOff)), "旧版里关着，不导入；场景里用到它们的绑定也跳过，和旧版一样")
	}
	if c.noResolve > 0 {
		c.leftOut(fmt.Sprintf("%d 条规则的 no_resolve", c.noResolve), "新版先解析域名再分流（3.3），这个标记不再需要")
	}
}

// addCondition converts one matching rule set into a new rule set.
func (c *converter) addCondition(r RuleSet, enabled bool, profile string) {
	cond := &condition{rule: r}
	label := fmt.Sprintf("规则 %s（%s）", r.Name, profile)
	if _, dup := c.conditions[r.ID]; dup {
		c.problem(label, "id 和别的规则重复")
		return
	}
	c.conditions[r.ID] = cond
	if !enabled {
		c.ruleSetsOff = append(c.ruleSetsOff, r.Name)
		return
	}
	if r.NoResolve {
		c.noResolve++
	}
	var out map[string]any
	switch r.Type {
	case "manual":
		rule := map[string]any{}
		if len(r.Domains) > 0 {
			rule["domain_suffix"] = r.Domains
		}
		if len(r.CIDRs) > 0 {
			rule["ip_cidr"] = r.CIDRs
		}
		if len(rule) == 0 {
			c.leftOut(label, "里面什么都没有：旧版也不用它")
			return
		}
		out = map[string]any{"type": "inline", "rules": []any{rule}}
	case "native":
		var rule map[string]any
		if err := json.Unmarshal(r.NativeRule, &rule); err != nil || len(rule) == 0 {
			c.problem(label, "sing-box 规则读不出来")
			return
		}
		out = map[string]any{"type": "inline", "rules": []any{rule}}
	case "application":
		rules, why := applicationRule(r)
		if why != "" {
			c.problem(label, why)
			return
		}
		out = map[string]any{"type": "inline", "rules": rules}
	case "url":
		if r.URL == "" {
			c.leftOut(label, "没有地址：旧版也不用它")
			return
		}
		out = map[string]any{"type": "remote", "format": remoteFormat(r), "url": r.URL}
		if via := r.FetchLineID; via != "" && via != config.Direct {
			to, known := c.lineIDs[via]
			switch {
			case !known:
				c.problem(label, "下载经过的线路不在旧库里")
				return
			case to == "" || to == unusable:
				c.problem(label, "下载经过的线路关着或旧版也用不了")
				return
			case c.lineTypes[to] == "openconnect" || c.lineTypes[to] == "tailscale":
				// A VPN line is not up while rule sets download, 3.4.
				c.leftOut(label+" 的下载线路", "原来经 VPN 线路下载，新版不能经 VPN 线路下载，改成直连；直连下不了就在配置里把 download_via 改成一条代理线路")
			case to != config.Direct:
				out["download_via"] = to
			}
		}
	default:
		c.problem(label, "规则类型 "+r.Type+" 新版不支持")
		return
	}
	cond.id = c.newID("rule", r.Name)
	out["id"], out["name"] = cond.id, r.Name
	c.ruleSets = append(c.ruleSets, out)
}

// remoteFormat is the format the old App downloaded a remote rule set as.
func remoteFormat(r RuleSet) string {
	switch r.Format {
	case "srs", "binary":
		return "binary"
	case "json", "source":
		return "source"
	}
	if strings.EqualFold(path.Ext(r.URL), ".json") {
		return "source"
	}
	return "binary"
}

// applicationRule matches the apps and processes of r as the old App did
// (Surge PROCESS-NAME): an app by the executables inside its bundle, a bare
// name with * and ? by the executable's name, an absolute path exactly,
// and one ending in / by prefix.
func applicationRule(r RuleSet) ([]any, string) {
	var names, paths, patterns []string
	for _, app := range r.Applications {
		bundle := strings.TrimSuffix(app.Path, "/")
		if bundle == "" || !strings.HasPrefix(bundle, "/") || path.Clean(bundle) != bundle {
			return nil, "应用 " + app.Name + " 只有 bundle id，没有路径：新版只能按可执行文件的路径匹配"
		}
		patterns = append(patterns, "^"+regexp.QuoteMeta(bundle)+"/")
	}
	for _, p := range r.Processes {
		switch {
		case strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/"):
			patterns = append(patterns, "^"+regexp.QuoteMeta(strings.TrimSuffix(p, "/"))+"/")
		case strings.HasPrefix(p, "/"):
			paths = append(paths, p)
		case strings.ContainsAny(p, "*?"):
			glob := regexp.QuoteMeta(p)
			glob = strings.ReplaceAll(strings.ReplaceAll(glob, `\*`, `[^/]*`), `\?`, `[^/]`)
			patterns = append(patterns, "(^|/)"+glob+"$")
		default:
			names = append(names, p)
		}
	}
	// One rule each: sing-box requires every field of a rule to match, the
	// old App any of its selectors; a rule set matches when any rule does.
	var rules []any
	if len(names) > 0 {
		rules = append(rules, map[string]any{"process_name": names})
	}
	if len(paths) > 0 {
		rules = append(rules, map[string]any{"process_path": paths})
	}
	if len(patterns) > 0 {
		rules = append(rules, map[string]any{"process_path_regex": patterns})
	}
	if len(rules) == 0 {
		return nil, "里面没有应用"
	}
	return rules, ""
}

// convertScenarios lays each scenario's bindings out in the order the old
// App matched them: by the order it kept from the import where there is
// one, a new condition after the last one of its rule set, a new binding
// at the end; core/config/rule_set_group.go of the old repository.
func (c *converter) convertScenarios() {
	scenarios := append([]Scenario(nil), c.lib.Scenarios...)
	for i, s := range scenarios {
		if s.ID == c.lib.ActiveScenarioID && i > 0 {
			scenarios = append(append([]Scenario{s}, scenarios[:i]...), scenarios[i+1:]...)
			break
		}
	}
	for _, s := range scenarios {
		label := "场景 " + s.Name
		if s.DefaultSubscriptionID != "" {
			c.problem(label, "默认出口是订阅，新版不支持")
			continue
		}
		selected := map[string]Binding{}
		owners := map[string]string{}
		var natural []string
		bad := false
		for _, b := range s.Bindings {
			if b.SubscriptionID != "" {
				c.problem(label, "有规则绑到订阅上，新版不支持")
				bad = true
				break
			}
			ids, ok := c.members[b.RuleSetID]
			if !ok {
				c.problem(label, "绑定的规则不在旧库里")
				bad = true
				break
			}
			if len(b.ConditionIDs) > 0 {
				member := map[string]bool{}
				for _, id := range ids {
					member[id] = true
				}
				for _, id := range b.ConditionIDs {
					if !member[id] {
						c.problem(label, "绑定选的匹配条件不在它的规则里")
						bad = true
					}
				}
				ids = b.ConditionIDs
			}
			for _, id := range ids {
				if bad {
					break
				}
				if _, dup := selected[id]; dup || c.conditions[id] == nil {
					c.problem(label, "绑定的匹配条件重复或不存在")
					bad = true
					break
				}
				selected[id], owners[id] = b, b.RuleSetID
				natural = append(natural, id)
			}
		}
		if bad {
			continue
		}
		order := append([]string(nil), s.MatchOrder...)
		seen := map[string]bool{}
		for _, id := range order {
			if _, ok := selected[id]; !ok || seen[id] {
				c.problem(label, "匹配顺序里的条件重复或不在绑定里")
				bad = true
				break
			}
			seen[id] = true
		}
		if bad {
			continue
		}
		for _, id := range natural {
			if seen[id] {
				continue
			}
			at := len(order)
			if len(s.MatchOrder) > 0 {
				for i := len(order) - 1; i >= 0; i-- {
					if owners[order[i]] == owners[id] {
						at = i + 1
						break
					}
				}
			}
			order = append(order[:at], append([]string{id}, order[at:]...)...)
			seen[id] = true
		}
		rules := []any{}
		for _, id := range order {
			cond := c.conditions[id]
			b := selected[id]
			line, ok := c.target(b.LineID)
			if !ok {
				c.problem(label, "绑定的线路不在旧库里")
				bad = true
				break
			}
			if line == unusable {
				c.problem(label, "绑定的线路旧版也用不了，这个场景旧版也连不上")
				bad = true
				break
			}
			// Off rule sets and lines skip the binding, as in the old App.
			if cond.id == "" || line == "" {
				continue
			}
			rule := map[string]any{"rule_set": cond.id, "line": line}
			if cond.rule.Invert {
				rule["invert"] = true
			}
			rules = append(rules, rule)
		}
		if bad {
			continue
		}
		final, ok := c.target(s.DefaultLineID)
		switch {
		case s.DefaultLineID == "":
			final = config.Direct
		case !ok:
			c.problem(label, "默认线路不在旧库里")
			continue
		case final == unusable:
			c.problem(label, "默认线路开着但旧版也用不了，这个场景旧版也连不上")
			continue
		case final == "":
			// The old App went direct when the default line was off.
			final = config.Direct
			c.leftOut(label+" 的默认线路", "关着或没导入，和旧版一样走直连")
		}
		if len(s.MatchSSIDs) > 0 {
			c.leftOut(label+" 按 Wi-Fi 自动切换", "新版不做按 SSID 切换场景（方案 3.3）")
		}
		c.scenarios = append(c.scenarios, map[string]any{"id": c.newID("scenario", s.Name), "name": s.Name, "rules": rules, "final": final})
	}
	if len(c.scenarios) == 0 {
		c.problem("场景", "没有能导入的场景")
	}
}

// target maps an old line or group id; "" when it is off.
func (c *converter) target(old string) (string, bool) {
	if to, known := c.lineIDs[old]; known {
		return to, true
	}
	if old == config.Direct {
		return config.Direct, true
	}
	return "", false
}

// emptyJSON reports whether raw holds nothing: null, or objects and arrays
// with nothing in them. The old App kept an empty {"tls": {}} on lines it
// imported with only the usual TLS fields.
func emptyJSON(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	var empty func(any) bool
	empty = func(v any) bool {
		switch x := v.(type) {
		case nil:
			return true
		case map[string]any:
			for _, child := range x {
				if !empty(child) {
					return false
				}
			}
			return true
		case []any:
			return len(x) == 0
		}
		return false
	}
	return empty(v)
}
