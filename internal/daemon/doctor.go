package daemon

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/kafeifei/xdial-next/internal/sysdns"
)

// SchemaDoctor is the result of doctor, ARCHITECTURE.md 6.6.
const SchemaDoctor = "xdial.doctor/v1"

// Check is one finding of doctor: what it concluded, from what, and what
// to do about it.
type Check struct {
	Name string `json:"name"`
	// Status is ok, warn, fail, or skip when the check does not apply.
	Status  string   `json:"status"`
	Summary string   `json:"summary"`
	Detail  []string `json:"detail,omitempty"`
	Hint    string   `json:"hint,omitempty"`
}

const (
	checkSkip = "skip"
	checkOK   = "ok"
	checkWarn = "warn"
	checkFail = "fail"
)

var severity = map[string]int{checkSkip: 0, checkOK: 1, checkWarn: 2, checkFail: 3}

// worse returns the more severe of two statuses.
func worse(a, b string) string {
	if severity[b] > severity[a] {
		return b
	}
	return a
}

// doctorWindow is how far back doctor looks for the engine's trouble.
const doctorWindow = 24 * time.Hour

// doctor reads the state, the event log and the system and says what is
// wrong, 6.6. It changes nothing and takes no lock across the system
// reads, so it answers while a connection is being made.
func (d *Daemon) doctor(json.RawMessage) reply {
	d.mu.Lock()
	configured := d.cfg != nil
	d.mu.Unlock()
	s := d.currentStatus()
	checks := []Check{
		checkConnection(s, configured),
		d.checkSystemDNS(s),
		d.checkSupplementals(),
		d.checkVPNs(),
		d.checkPhysicalDNS(),
		checkEndpoints(s),
		checkGroups(s),
		d.checkResources(),
		checkEngine(d.events.recent(recentLines), time.Now()),
	}
	return reply{schema: SchemaDoctor, result: map[string]any{"checks": checks}}
}

func checkConnection(s Status, configured bool) Check {
	c := Check{Name: "connection"}
	switch {
	case !configured:
		c.Status, c.Summary, c.Hint = checkFail, "还没有配置", "用 xdial config apply 提交配置"
	case s.State == "connected":
		c.Status, c.Summary = checkOK, fmt.Sprintf("已连接，场景 %s", s.Scenario)
	case s.Intent == "disconnected":
		c.Status, c.Summary, c.Hint = checkWarn, "没有连接", "用 xdial connect 连接"
	case s.State == "connecting":
		c.Status, c.Summary, c.Hint = checkWarn, "正在连接", "等一会儿再看；一直这样就看 xdial logs"
	default:
		c.Status, c.Summary = checkFail, "要求连接，但连接失败了"
		c.Hint = "看 xdial logs；网络变化或手动 xdial connect 时会再试"
	}
	if s.LastError != "" && s.State != "connected" {
		c.Detail = []string{s.LastError}
	}
	return c
}

func (d *Daemon) checkSystemDNS(s Status) Check {
	c := Check{Name: "system_dns"}
	if s.State != "connected" {
		c.Status, c.Summary = checkSkip, "没有连接"
		return c
	}
	published, first, err := d.sys.Resolver(d.opts.Layout.DNSKey())
	switch {
	case err != nil:
		c.Status, c.Summary, c.Detail = checkFail, "读不到系统的解析器", []string{err.Error()}
	case !published:
		c.Status, c.Summary = checkFail, "XDial 的解析器不在系统里"
		c.Hint = "daemon 会自动补写；一直这样就看 xdial logs"
	case first != resolverAddress.String():
		c.Status, c.Summary = checkFail, fmt.Sprintf("系统的第一解析器是 %s，不是 XDial 的 %s：系统查询不经过 sing-box", first, resolverAddress)
		c.Hint = "别的 VPN 或网络工具改了系统的 DNS；断开它，或者重新 xdial connect"
	default:
		c.Status, c.Summary = checkOK, fmt.Sprintf("系统的第一解析器是 XDial 的 %s", resolverAddress)
	}
	return c
}

func (d *Daemon) checkSupplementals() Check {
	c := Check{Name: "split_dns"}
	list, err := d.sys.Supplementals()
	switch {
	case err != nil:
		c.Status, c.Summary, c.Detail = checkWarn, "读不到系统的解析器列表", []string{err.Error()}
	case len(list) == 0:
		c.Status, c.Summary = checkOK, "没有按域名指定的解析器"
	default:
		c.Status = checkWarn
		c.Summary = fmt.Sprintf("%d 个域名有自己的解析器，这些域名的查询不经过 XDial", len(list))
		for _, s := range list {
			line := fmt.Sprintf("%s → %s", s.Domain, strings.Join(s.Servers, ", "))
			if s.Interface != "" {
				line += "（" + s.Interface + "）"
			}
			c.Detail = append(c.Detail, line)
		}
		c.Hint = "它们来自别的 VPN 的分割 DNS 或 /etc/resolver 下的文件；要让这些域名经过 XDial，就断开那个 VPN 或删掉文件"
	}
	return c
}

func (d *Daemon) checkVPNs() Check {
	c := Check{Name: "other_vpn"}
	vpns, err := d.sys.VPNs()
	for _, name := range vpns {
		c.Detail = append(c.Detail, fmt.Sprintf("VPN 服务 %q 连着", name))
	}
	if iface, err := d.sys.PhysicalInterface(); err == nil && sysdns.IsTunnel(iface) {
		c.Detail = append(c.Detail, fmt.Sprintf("系统的主网络服务在隧道 %s 上", iface))
	}
	switch {
	case len(c.Detail) > 0:
		c.Status, c.Summary = checkWarn, "有别的 VPN 连着"
		c.Hint = "全局 VPN 会和 XDial 争路由和系统 DNS；XDial 的流量经它出去，它断开时 XDial 跟着重连"
	case err != nil:
		c.Status, c.Summary, c.Detail = checkWarn, "读不到 VPN 服务", []string{err.Error()}
	default:
		c.Status, c.Summary = checkOK, "没有别的 VPN 连着"
	}
	return c
}

func (d *Daemon) checkPhysicalDNS() Check {
	c := Check{Name: "physical_dns"}
	servers, err := d.sys.PhysicalDNS()
	if err != nil {
		c.Status, c.Summary, c.Detail = checkFail, "读不到物理网络的 DNS", []string{err.Error()}
		return c
	}
	servers = usablePhysical(servers)
	if len(servers) == 0 {
		c.Status, c.Summary, c.Hint = checkFail, "物理网络没有 DNS 服务器", "连上网络后再试"
		return c
	}
	if len(servers) > 1 {
		c.Detail = []string{fmt.Sprintf("只用第一个（3.3），其余：%v", servers[1:])}
	}
	if err := d.sys.Upstream(servers[0]); err != nil {
		c.Status = checkFail
		c.Summary = fmt.Sprintf("物理网络的 DNS %s 解析不了 %s", servers[0], sysdns.UpstreamName)
		c.Detail = append([]string{err.Error()}, c.Detail...)
		c.Hint = "direct 的域名和线路服务器的域名都经它解析（3.3）；换个网络，或者检查路由器的 DNS"
		return c
	}
	c.Status, c.Summary = checkOK, fmt.Sprintf("物理网络的 DNS %s 能解析", servers[0])
	return c
}

func checkEndpoints(s Status) Check {
	c := Check{Name: "endpoints", Status: checkOK}
	if len(s.Endpoints) == 0 {
		c.Status, c.Summary = checkSkip, "当前连接没有 AnyConnect 或 Tailscale 线路"
		return c
	}
	counts := map[string]int{}
	var hints []string
	for _, id := range slices.Sorted(maps.Keys(s.Endpoints)) {
		e := s.Endpoints[id]
		counts[e.State]++
		line := fmt.Sprintf("%s（%s）：%s", id, e.Type, endpointState(e.State))
		switch e.State {
		case "connected":
		case "auth_required":
			c.Status = worse(c.Status, checkWarn)
			switch {
			case e.Type == "tailscale":
				hints = append(hints, "xdial tailscale login "+id)
			case e.BrowserAuth:
				hints = append(hints, id+" 要在浏览器里登录，等 App（M5）")
			default:
				hints = append(hints, "检查 "+id+" 的凭据")
			}
			if e.AuthMessage != "" {
				line += "，" + e.AuthMessage
			}
		case "failed":
			c.Status = worse(c.Status, checkFail)
			if e.Error != "" {
				line += "，" + e.Error
			}
			hints = append(hints, "看 xdial status 里 "+id+" 的错误")
		default:
			c.Status = worse(c.Status, checkWarn)
		}
		c.Detail = append(c.Detail, line)
	}
	c.Summary = fmt.Sprintf("%d 条线路：%d 已连接，%d 要登录，%d 失败，%d 正在连接", len(s.Endpoints),
		counts["connected"], counts["auth_required"], counts["failed"], counts["connecting"])
	c.Hint = strings.Join(hints, "；")
	return c
}

func endpointState(state string) string {
	switch state {
	case "connected":
		return "已连接"
	case "auth_required":
		return "要登录"
	case "failed":
		return "失败"
	}
	return "正在连接"
}

func checkGroups(s Status) Check {
	c := Check{Name: "groups", Status: checkOK}
	if len(s.Groups) == 0 {
		c.Status, c.Summary = checkSkip, "当前连接没有线路组"
		return c
	}
	var untested []string
	for _, id := range slices.Sorted(maps.Keys(s.Groups)) {
		g := s.Groups[id]
		passed := 0
		for _, m := range g.Members {
			if m.TestedAt != nil {
				passed++
			}
		}
		c.Detail = append(c.Detail, fmt.Sprintf("%s（%s）：在用 %s，%d/%d 个成员测通", id, g.Type, g.Now, passed, len(g.Members)))
		// urltest tests on its own; sing-box drops a member's result when
		// its test fails, so no result means it has not passed.
		if g.Type == "urltest" && passed == 0 {
			untested = append(untested, id)
		}
	}
	if len(untested) > 0 {
		c.Status = checkWarn
		c.Summary = fmt.Sprintf("组 %s 没有测通的成员", strings.Join(untested, "、"))
		c.Hint = "刚连上时可能还没测完；一直这样就用 xdial line test 看每个成员的错误"
		return c
	}
	c.Summary = fmt.Sprintf("%d 个组", len(s.Groups))
	return c
}

func (d *Daemon) checkResources() Check {
	c := Check{Name: "resources", Status: checkOK}
	remote := 0
	note := func(kind, id string, cached bool, fetched *time.Time, err *string) {
		remote++
		switch {
		case err != nil && cached:
			c.Status = worse(c.Status, checkWarn)
			c.Detail = append(c.Detail, fmt.Sprintf("%s %s 上次更新失败，用的是 %s 下载的：%s", kind, id, fetched.Local().Format(time.DateTime), *err))
		case err != nil:
			c.Status = worse(c.Status, checkFail)
			c.Detail = append(c.Detail, fmt.Sprintf("%s %s 下载失败，还没有缓存：%s", kind, id, *err))
		case !cached:
			c.Status = worse(c.Status, checkWarn)
			c.Detail = append(c.Detail, fmt.Sprintf("%s %s 还没下载", kind, id))
		}
	}
	for _, r := range d.ruleSetInfos() {
		if r.Type != "remote" {
			continue
		}
		var msg *string
		if r.LastError != nil {
			m := fmt.Sprintf("%s（%s）", r.LastError.Message, r.LastError.Code)
			msg = &m
		}
		note("规则集", r.ID, r.Cached, r.FetchedAt, msg)
	}
	for _, s := range d.subscriptionInfos() {
		var msg *string
		if s.LastError != nil {
			m := fmt.Sprintf("%s（%s）", s.LastError.Message, s.LastError.Code)
			msg = &m
		}
		note("订阅", s.ID, s.Cached, s.FetchedAt, msg)
	}
	switch {
	case remote == 0:
		c.Status, c.Summary = checkSkip, "没有远程规则集和订阅"
	case len(c.Detail) == 0:
		c.Summary = fmt.Sprintf("%d 个远程规则集和订阅都已下载", remote)
	default:
		c.Summary = fmt.Sprintf("%d 个远程规则集和订阅里有 %d 个有问题", remote, len(c.Detail))
		c.Hint = "用 xdial rule-set update、xdial subscription update 重试；用到没下载的规则集或订阅的场景连不上"
	}
	return c
}

// engineTrouble are the events doctor counts: the engine dying or not
// answering, reconnecting giving up, the system resolver going away.
var engineTrouble = []string{"engine_exited", "engine_failed", "engine_unresponsive", "retry_stopped", "dns_hold_failed", "dns_check_failed"}

func checkEngine(events []Event, now time.Time) Check {
	c := Check{Name: "engine", Status: checkOK}
	counts := map[string]int{}
	last := map[string]time.Time{}
	for _, e := range events {
		if now.Sub(e.Time) > doctorWindow || !slices.Contains(engineTrouble, e.Type) {
			continue
		}
		counts[e.Type]++
		last[e.Type] = e.Time
	}
	for _, typ := range engineTrouble {
		if counts[typ] == 0 {
			continue
		}
		c.Status = worse(c.Status, checkWarn)
		if typ == "retry_stopped" {
			c.Status = checkFail
		}
		c.Detail = append(c.Detail, fmt.Sprintf("%s %d 次，最近一次 %s", typ, counts[typ], last[typ].Local().Format(time.DateTime)))
	}
	if len(c.Detail) == 0 {
		c.Summary = "最近 24 小时引擎没有崩溃、不回答或停止重连"
		return c
	}
	c.Summary = "最近 24 小时引擎出过问题"
	c.Detail = append(c.Detail, fmt.Sprintf("只看最近 %d 条事件", recentLines))
	c.Hint = "用 xdial logs 看经过"
	return c
}
