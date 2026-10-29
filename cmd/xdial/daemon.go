package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kafeifei/xdial-next/internal/api"
	"github.com/kafeifei/xdial-next/internal/buildinfo"
	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/daemon"
	"github.com/kafeifei/xdial-next/internal/paths"
	"github.com/kafeifei/xdial-next/internal/store"
	"github.com/kafeifei/xdial-next/internal/sysdns"
)

// layoutRoot prefixes every daemon path and daemonUID is the owner the
// daemon's socket must have; only tests change them.
var (
	layoutRoot string
	daemonUID  uint32
)

func layout() paths.Layout { return paths.Layout{ID: buildinfo.Identity, Root: layoutRoot} }

func daemonCommands() []*command {
	return []*command{
		{Path: []string{"daemon", "install"}, Output: "xdial.daemon.install/v1", run: runDaemonInstall,
			Summary: "以 root 安装 daemon：拷贝二进制、写 launchd 配置并启动（ARCHITECTURE.md 6.1），要 sudo",
			Options: []option{jsonOption}},
		{Path: []string{"daemon", "uninstall"}, Output: "xdial.daemon.uninstall/v1", run: runDaemonUninstall,
			Summary: "断开并卸载 daemon，要 sudo；--purge 连数据一起删",
			Options: []option{jsonOption, {Name: "--purge", Summary: "同时删除配置、凭据和缓存"}}},
		{Path: []string{"daemon", "run"}, Output: "xdial.daemon.run/v1", run: runDaemon,
			Summary: "在前台运行 daemon，由 launchd 调用", Options: []option{jsonOption}},
		{Path: []string{"status"}, Output: daemon.SchemaStatus, run: apiCommand("status", nil),
			Summary: "显示连接状态", Options: []option{jsonOption}},
		{Path: []string{"connect"}, Output: daemon.SchemaStatus, run: runConnect,
			Summary: "连接；不写场景就用上次的场景",
			Options: []option{jsonOption, {Name: "--scenario", Value: "<id>", Summary: "连接时使用的场景"}}},
		{Path: []string{"disconnect"}, Output: daemon.SchemaStatus, run: apiCommand("disconnect", nil),
			Summary: "断开连接", Options: []option{jsonOption}},
		{Path: []string{"scenario", "use"}, Args: []string{"<id>"}, Output: daemon.SchemaStatus, run: runScenarioUse,
			Summary: "切换场景；连接中会重载一次", Options: []option{jsonOption}},
		{Path: []string{"config", "apply"}, Args: []string{"<文件>"}, Output: daemon.SchemaConfigApply, run: runConfigApply,
			Summary: "把配置整份提交给 daemon（ARCHITECTURE.md 4.1）",
			Options: []option{jsonOption,
				{Name: "--dry-run", Summary: "只检查并列出变化，不提交"},
				{Name: "--if-match", Value: "<revision>", Summary: "配置已被改过时拒绝"}}},
		{Path: []string{"config", "export"}, Output: daemon.SchemaConfigExport, run: apiCommand("config.export", nil),
			Summary: "导出 daemon 当前的配置", Options: []option{jsonOption}},
		{Path: []string{"secret", "set"}, Args: []string{"<名字>"}, Output: daemon.SchemaSecret, run: runSecretSet,
			Summary: "从 stdin 读凭据的值并保存；stdin 是终端时不回显（ARCHITECTURE.md 4.6）", Options: []option{jsonOption}},
		{Path: []string{"secret", "list"}, Output: daemon.SchemaSecretList, run: apiCommand("secret.list", nil),
			Summary: "列出凭据的名字、是否已设置和引用方，不显示值", Options: []option{jsonOption}},
		{Path: []string{"secret", "rm"}, Args: []string{"<名字>"}, Output: daemon.SchemaSecret, run: runSecretRemove,
			Summary: "删除凭据；仍被引用时拒绝", Options: []option{jsonOption}},
		{Path: []string{"rule-set", "list"}, Output: daemon.SchemaRuleSetList, run: runRuleSetList,
			Summary: "列出规则集：远程规则集有没有下载、下载时间、规则条数和上次的错误", Options: []option{jsonOption}},
		{Path: []string{"rule-set", "update"}, Args: []string{"[<id>...]"}, Output: daemon.SchemaRuleSetUpdate, run: runRuleSetUpdate,
			Summary: "现在下载远程规则集，不写 id 就下载全部；新内容在下一次连接或切场景时生效（ARCHITECTURE.md 3.4）",
			Options: []option{jsonOption}},
		{Path: []string{"subscription", "list"}, Output: daemon.SchemaSubscriptionList, run: runSubscriptionList,
			Summary: "列出订阅：有没有下载、节点数、规则数、规则用到的策略名、不支持而没收的条目和上次的错误", Options: []option{jsonOption}},
		{Path: []string{"subscription", "show"}, Args: []string{"<id>"}, Output: daemon.SchemaSubscriptionShow, run: runSubscriptionShow,
			Summary: "列出订阅的节点（名字、类型、服务器，不含凭据）和策略名，用来写组的 filter 和场景的 policies", Options: []option{jsonOption}},
		{Path: []string{"subscription", "update"}, Args: []string{"[<id>...]"}, Output: daemon.SchemaSubscriptionUpdate, run: runSubscriptionUpdate,
			Summary: "现在下载订阅，不写 id 就下载全部；新内容在下一次连接或切场景时生效（ARCHITECTURE.md 1.5）", Options: []option{jsonOption}},
		{Path: []string{"logs"}, Output: "xdial.logs/v1", run: runLogs,
			Summary: "显示 daemon 的事件日志",
			Options: []option{jsonOption,
				{Name: "--follow", Summary: "持续输出新事件"},
				{Name: "--lines", Value: "<n>", Summary: "先输出最近的多少条，最多 200"}}},
	}
}

// call runs one API method and prints the reply: as it came with --json,
// through text otherwise.
func call(ctx *context_, method string, params any, text func(io.Writer, json.RawMessage)) int {
	client, err := api.Dial(layout().Socket(), daemonUID)
	if err != nil {
		return ctx.out.Fail(err)
	}
	defer client.Close()
	code := cli.ExitOK
	err = client.Call(method, params, func(resp api.Response) bool {
		if !resp.OK {
			code = ctx.out.Fail(resp.Error)
			return false
		}
		if ctx.out.JSON {
			code = ctx.out.Print(resp.Envelope())
		} else if text != nil && string(resp.Result) != "null" {
			text(ctx.out.Stdout, resp.Result)
		}
		return true
	})
	if err != nil {
		return ctx.out.Fail(err)
	}
	return code
}

func apiCommand(method string, params any) func(*context_) int {
	return func(ctx *context_) int { return call(ctx, method, params, printStatusOrRaw) }
}

func printStatusOrRaw(w io.Writer, raw json.RawMessage) {
	var s daemon.Status
	if json.Unmarshal(raw, &s) == nil && s.State != "" {
		fmt.Fprintf(w, "状态：%s", s.State)
		if s.Scenario != "" {
			fmt.Fprintf(w, "，场景 %s", cli.Escape(s.Scenario))
		}
		fmt.Fprintln(w)
		if s.LastError != "" {
			fmt.Fprintln(w, "原因：", cli.Escape(s.LastError))
		}
		return
	}
	var pretty map[string]any
	if json.Unmarshal(raw, &pretty) == nil {
		b, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Fprintln(w, cli.Escape(string(b)))
	}
}

func runConnect(ctx *context_) int {
	return call(ctx, "connect", map[string]string{"scenario": ctx.options["--scenario"]}, printStatusOrRaw)
}

func runScenarioUse(ctx *context_) int {
	return call(ctx, "scenario.use", map[string]string{"id": ctx.args[0]}, printStatusOrRaw)
}

func runConfigApply(ctx *context_) int {
	data, err := readFile(ctx.args[0])
	if err != nil {
		return ctx.out.Fail(err)
	}
	_, dryRun := ctx.options["--dry-run"]
	params := map[string]any{"content": string(data), "dry_run": dryRun, "if_match": ctx.options["--if-match"]}
	return call(ctx, "config.apply", params, func(w io.Writer, raw json.RawMessage) {
		var r daemon.ApplyResult
		if json.Unmarshal(raw, &r) != nil {
			return
		}
		if r.Applied {
			fmt.Fprintf(w, "已提交（revision %s）\n", short(r.Revision))
		} else {
			fmt.Fprintf(w, "检查通过，没有提交（revision %s）\n", short(r.Revision))
		}
		for _, c := range r.Changes {
			fmt.Fprintf(w, "  %s %s %s\n", c.Change, c.Kind, cli.Escape(c.ID))
		}
		if len(r.MissingSecrets) > 0 {
			fmt.Fprintf(w, "还没设置的凭据：%s\n", cli.Escape(strings.Join(r.MissingSecrets, "、")))
		}
		for _, p := range r.Pending {
			fmt.Fprintln(w, "没能检查：", cli.Escape(p))
		}
	})
}

func short(revision string) string {
	if len(revision) > 12 {
		return revision[:12]
	}
	return revision
}

// runSecretSet reads the value from stdin, never from arguments or the
// environment, with echo off on a terminal, and strips one trailing line
// ending, ARCHITECTURE.md 4.6.
func runSecretSet(ctx *context_) int {
	var value []byte
	var err error
	if f, ok := ctx.stdin.(*os.File); ok && isTerminal(f) {
		fmt.Fprint(ctx.out.Stderr, "输入凭据的值（不回显）：")
		value, err = readHidden(f)
		fmt.Fprintln(ctx.out.Stderr)
	} else {
		value, err = io.ReadAll(io.LimitReader(ctx.stdin, 1<<20))
	}
	if err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInputRead, "", "读 stdin 出错：%v", err))
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(value), "\n"), "\r")
	return call(ctx, "secret.set", map[string]string{"name": ctx.args[0], "value": s}, func(w io.Writer, raw json.RawMessage) {
		var r daemon.SecretRef
		if json.Unmarshal(raw, &r) == nil {
			fmt.Fprintf(w, "已保存凭据 %s，引用方：%s\n", cli.Escape(r.Name), cli.Escape(strings.Join(r.References, "、")))
		}
	})
}

func runSecretRemove(ctx *context_) int {
	return call(ctx, "secret.rm", map[string]string{"name": ctx.args[0]}, func(w io.Writer, raw json.RawMessage) {
		fmt.Fprintln(w, "已删除凭据", cli.Escape(ctx.args[0]))
	})
}

func runLogs(ctx *context_) int {
	lines := 50
	if v, ok := ctx.options["--lines"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return ctx.out.Fail(cli.Errorf(cli.CodeUsage, "", "--lines 要是正整数"))
		}
		lines = n
	}
	_, follow := ctx.options["--follow"]
	return call(ctx, "logs", map[string]any{"lines": lines, "follow": follow}, func(w io.Writer, raw json.RawMessage) {
		var e daemon.Event
		if json.Unmarshal(raw, &e) == nil {
			fields, _ := json.Marshal(e.Fields)
			if string(fields) == "null" {
				fields = nil
			}
			fmt.Fprintf(w, "%s %s %s\n", e.Time.Local().Format(time.DateTime), e.Type, cli.Escape(string(fields)))
		}
	})
}

// requireRoot is for the commands that install, remove or run the daemon.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return cli.Errorf(cli.CodeAPIPermission, "加 sudo 再运行", "这个命令需要 root")
	}
	return nil
}

func runDaemon(ctx *context_) int {
	if err := requireRoot(); err != nil {
		return ctx.out.Fail(err)
	}
	exe, err := os.Executable()
	if err != nil {
		return ctx.out.Fail(err)
	}
	d, err := daemon.New(daemon.Options{Layout: layout(), Executable: exe})
	if err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "daemon 准备失败：%v", err))
	}
	run, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := d.Run(run); err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "daemon 退出：%v", err))
	}
	return ctx.out.Succeed("xdial.daemon.run/v1", map[string]any{"stopped": true}, nil)
}

// plistTemplate is the launchd job, 6.1. launchd kills what is left of the
// daemon's process group when it exits (AbandonProcessGroup false), so an
// engine or resolver session cannot outlive it; ThrottleInterval spaces
// restarts; ExitTimeOut leaves room for a disconnect before SIGKILL. Only
// panics reach stderr; the daemon trims the file when it starts.
const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>daemon</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>AbandonProcessGroup</key>
	<false/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>ExitTimeOut</key>
	<integer>20</integer>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`

type installReport struct {
	Identity string `json:"identity"`
	Binary   string `json:"binary"`
	Plist    string `json:"plist"`
	Socket   string `json:"socket"`
}

// runDaemonInstall copies the running binary to a root-owned path, writes
// the launchd job and starts it, ARCHITECTURE.md 6.1. An installed daemon
// is booted out first, which disconnects it, so installing again upgrades:
// the binary is replaced by rename, never overwritten in place, and the
// new daemon resumes the connection if it was up.
func runDaemonInstall(ctx *context_) int {
	if err := requireRoot(); err != nil {
		return ctx.out.Fail(err)
	}
	l := layout()
	exe, err := os.Executable()
	if err != nil {
		return ctx.out.Fail(err)
	}
	// Everything that can fail on the caller's input is checked and the
	// copy staged before the running daemon is stopped, so a bad source
	// leaves the installed daemon running.
	for _, dir := range []struct {
		path string
		perm os.FileMode
	}{{l.Data(), 0o755}, {filepath.Dir(l.Bin()), 0o755}, {l.Private(), 0o700}, {filepath.Dir(l.Plist()), 0o755}} {
		if err := store.EnsureDir(dir.path, dir.perm); err != nil {
			return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "准备目录 %s 失败：%v", dir.path, err))
		}
	}
	staged, err := stageBinary(exe, filepath.Dir(l.Bin()))
	if err != nil {
		return ctx.out.Fail(err)
	}
	defer os.Remove(staged)
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+l.ID).Run()
	if err := os.Rename(staged, l.Bin()); err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "替换二进制失败：%v", err))
	}
	plist := fmt.Sprintf(plistTemplate, l.ID, l.Bin(), l.DaemonLog(), l.DaemonLog())
	if err := store.WriteFile(l.Plist(), []byte(plist), 0o644); err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "写 launchd 配置失败：%v", err))
	}
	if out, err := exec.Command("/bin/launchctl", "bootstrap", "system", l.Plist()).CombinedOutput(); err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "launchctl bootstrap 失败：%v：%s", err, strings.TrimSpace(string(out))))
	}
	deadline := time.Now().Add(15 * time.Second)
	var build string
	for build == "" {
		if c, err := api.Dial(l.Socket(), daemonUID); err == nil {
			_ = c.Call("version", nil, func(r api.Response) bool {
				var v struct {
					Build string `json:"build"`
				}
				if r.OK && json.Unmarshal(r.Result, &v) == nil {
					build = v.Build
				}
				return true
			})
			c.Close()
		}
		if build == "" && time.Now().After(deadline) {
			return ctx.out.Fail(cli.Errorf(cli.CodeDaemonUnreachable, "看 "+l.DaemonLog(), "daemon 装好了，但 15 秒内没有起来"))
		}
		time.Sleep(200 * time.Millisecond)
	}
	if build != buildinfo.Build() {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "起来的 daemon 是 %s，不是刚装的 %s", build, buildinfo.Build()))
	}
	report := installReport{Identity: l.ID, Binary: l.Bin(), Plist: l.Plist(), Socket: l.Socket()}
	return ctx.out.Succeed("xdial.daemon.install/v1", report, func(w io.Writer) {
		fmt.Fprintf(w, "daemon %s 已安装并启动\n", l.ID)
	})
}

// stageBinary copies src, the xdial being run, to a new temporary file in
// dir, the root-owned bin directory, and returns its path, 6.1. The trust in what is copied rests on whoever controls
// src: the file must be a regular file owned by root or by the user who ran
// sudo, writable by nobody else, in a directory nobody else can change (or
// one with the sticky bit, where nobody else can replace it). It is opened
// without following a symlink and copied, synced and closed before the
// caller renames it into place, so launchd never starts a half-written
// file. A
// process of that same user could still swap src just before; it could as
// well have swapped it before sudo ran, so this does not try to stop it.
// Signed builds check the copy's signature before the rename (M6).
func stageBinary(src, dir string) (string, error) {
	resolved, err := filepath.EvalSymlinks(src)
	if err != nil {
		return "", cli.Errorf(cli.CodeInputRead, "", "找不到 %s：%v", src, err)
	}
	owners := []uint32{0}
	if id, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32); err == nil {
		owners = append(owners, uint32(id))
	}
	if err := ownedBy(filepath.Dir(resolved), owners, true); err != nil {
		return "", err
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", cli.Errorf(cli.CodeInputRead, "", "打不开 %s：%v", resolved, err)
	}
	defer f.Close()
	// What is checked is the file that was opened and is read below, not
	// whatever the path names by then.
	info, err := f.Stat()
	if err != nil {
		return "", cli.Errorf(cli.CodeInputRead, "", "%v", err)
	}
	if !info.Mode().IsRegular() {
		return "", cli.Errorf(cli.CodeInputPermission, "", "%s 不是普通文件", resolved)
	}
	if err := ownedInfo(resolved, info, owners, false); err != nil {
		return "", err
	}
	binary, err := io.ReadAll(io.LimitReader(f, 1<<30))
	if err != nil {
		return "", cli.Errorf(cli.CodeInputRead, "", "读 %s 出错：%v", resolved, err)
	}
	staged, err := store.Stage(dir, "xdial", binary, 0o755)
	if err != nil {
		return "", cli.Errorf(cli.CodeInternal, "", "拷贝二进制失败：%v", err)
	}
	return staged, nil
}

// ownedBy refuses path unless one of owners owns it and nobody else can
// write it; a directory with the sticky bit may be writable by others.
func ownedBy(path string, owners []uint32, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return cli.Errorf(cli.CodeInputRead, "", "%v", err)
	}
	return ownedInfo(path, info, owners, dir)
}

func ownedInfo(path string, info os.FileInfo, owners []uint32, dir bool) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !slices.Contains(owners, st.Uid) {
		return cli.Errorf(cli.CodeInputPermission, "把 xdial 放到自己或 root 的目录里再装", "%s 的属主不是 root 也不是运行 sudo 的用户", path)
	}
	if info.Mode().Perm()&0o022 != 0 && (!dir || info.Mode()&os.ModeSticky == 0) {
		return cli.Errorf(cli.CodeInputPermission, "chmod go-w 之后再装", "%s 属主以外的人能改", path)
	}
	acl, err := hasACL(path)
	if err != nil {
		return cli.Errorf(cli.CodeInputPermission, "", "没能检查 %s 的 ACL：%v", path, err)
	}
	if acl {
		return cli.Errorf(cli.CodeInputPermission, "chmod -N 去掉 ACL 之后再装", "%s 带 ACL，别的用户可能改得了它", path)
	}
	return nil
}

// runDaemonUninstall boots the daemon out, which makes it disconnect, then
// removes what install put down; --purge removes the data too, 6.1.
func runDaemonUninstall(ctx *context_) int {
	if err := requireRoot(); err != nil {
		return ctx.out.Fail(err)
	}
	l := layout()
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+l.ID).Run()
	// The resolver key goes with the daemon's session; remove it again in
	// case an older daemon left one that is not temporary.
	_ = sysdns.Clear(l.DNSKey())
	_, purge := ctx.options["--purge"]
	removed := []string{}
	targets := []string{l.Plist(), filepath.Dir(l.Bin()), l.SocketDir()}
	// The shared directory holds only the connection lock; it goes with the
	// last identity installed.
	other := paths.Layout{ID: paths.Release, Root: l.Root}
	if l.ID == paths.Release {
		other.ID = paths.Debug
	}
	if _, err := os.Lstat(other.Plist()); errors.Is(err, os.ErrNotExist) {
		targets = append(targets, l.SharedDir())
	}
	if purge {
		targets = append(targets, l.Data())
	}
	for _, path := range targets {
		if _, err := os.Lstat(path); err == nil {
			if err := os.RemoveAll(path); err != nil {
				return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "删除 %s 失败：%v", path, err))
			}
			removed = append(removed, path)
		}
	}
	return ctx.out.Succeed("xdial.daemon.uninstall/v1", map[string]any{"identity": l.ID, "removed": removed, "purged": purge}, func(w io.Writer) {
		fmt.Fprintf(w, "daemon %s 已卸载\n", l.ID)
		for _, p := range removed {
			fmt.Fprintln(w, "  删除了", p)
		}
	})
}

func runRuleSetList(ctx *context_) int {
	return call(ctx, "rule_set.list", nil, func(w io.Writer, raw json.RawMessage) {
		var r struct {
			RuleSets []daemon.RuleSetInfo `json:"rule_sets"`
		}
		_ = json.Unmarshal(raw, &r)
		for _, s := range r.RuleSets {
			line := fmt.Sprintf("%s  %s", s.ID, s.Type)
			switch {
			case s.Type == "inline":
				line += fmt.Sprintf("，%d 条规则", s.Rules)
			case s.Cached:
				line += fmt.Sprintf("，%d 条规则，%s 下载", s.Rules, s.FetchedAt.Local().Format("2006-01-02 15:04"))
			default:
				line += "，还没下载"
			}
			fmt.Fprintln(w, cli.Escape(line))
			if s.LastError != nil {
				fmt.Fprintln(w, "  上次下载失败：", cli.Escape(s.LastError.Message))
			}
		}
	})
}

func runRuleSetUpdate(ctx *context_) int {
	return call(ctx, "rule_set.update", map[string]any{"ids": ctx.args}, func(w io.Writer, raw json.RawMessage) {
		var r struct {
			Updated []struct {
				ID      string `json:"id"`
				Changed bool   `json:"changed"`
				Rules   int    `json:"rules"`
			} `json:"updated"`
		}
		_ = json.Unmarshal(raw, &r)
		for _, u := range r.Updated {
			state := "没有变化"
			if u.Changed {
				state = "已更新"
			}
			fmt.Fprintf(w, "%s：%s，%d 条规则\n", cli.Escape(u.ID), state, u.Rules)
		}
		if len(r.Updated) > 0 {
			fmt.Fprintln(w, "新内容在下一次连接或切场景时生效")
		}
	})
}

func runSubscriptionList(ctx *context_) int {
	return call(ctx, "subscription.list", nil, func(w io.Writer, raw json.RawMessage) {
		var r struct {
			Subscriptions []daemon.SubscriptionInfo `json:"subscriptions"`
		}
		_ = json.Unmarshal(raw, &r)
		for _, s := range r.Subscriptions {
			line := s.ID
			if s.Cached {
				line += fmt.Sprintf("  %s，%d 个节点，%d 条规则，%s 下载", s.Format, s.Nodes, s.Rules, s.FetchedAt.Local().Format("2006-01-02 15:04"))
			} else {
				line += "  还没下载"
			}
			fmt.Fprintln(w, cli.Escape(line))
			for _, p := range s.Policies {
				fmt.Fprintf(w, "  策略 %s：%d 条规则\n", cli.Escape(p.Name), p.Rules)
			}
			if len(s.Unsupported) > 0 {
				fmt.Fprintln(w, "  没收的条目：", cli.Escape(fmt.Sprint(s.Unsupported)))
			}
			if s.LastError != nil {
				fmt.Fprintln(w, "  上次下载失败：", cli.Escape(s.LastError.Message))
			}
		}
	})
}

func runSubscriptionShow(ctx *context_) int {
	return call(ctx, "subscription.show", map[string]any{"id": ctx.args[0]}, func(w io.Writer, raw json.RawMessage) {
		var r struct {
			Nodes    []daemon.NodeInfo   `json:"nodes"`
			Policies []daemon.PolicyInfo `json:"policies"`
		}
		_ = json.Unmarshal(raw, &r)
		fmt.Fprintln(w, "节点：")
		for _, n := range r.Nodes {
			fmt.Fprintln(w, " ", cli.Escape(fmt.Sprintf("%s  %s %s:%d", n.Name, n.Type, n.Server, n.ServerPort)))
		}
		fmt.Fprintln(w, "策略：")
		for _, p := range r.Policies {
			fmt.Fprintln(w, " ", cli.Escape(fmt.Sprintf("%s（%d 条规则）", p.Name, p.Rules)))
		}
	})
}

func runSubscriptionUpdate(ctx *context_) int {
	return call(ctx, "subscription.update", map[string]any{"ids": ctx.args}, func(w io.Writer, raw json.RawMessage) {
		var r struct {
			Updated []struct {
				ID      string `json:"id"`
				Changed bool   `json:"changed"`
				Nodes   int    `json:"nodes"`
				Rules   int    `json:"rules"`
			} `json:"updated"`
		}
		_ = json.Unmarshal(raw, &r)
		for _, u := range r.Updated {
			state := "没有变化"
			if u.Changed {
				state = "已更新"
			}
			fmt.Fprintf(w, "%s：%s，%d 个节点，%d 条规则\n", cli.Escape(u.ID), state, u.Nodes, u.Rules)
		}
		if len(r.Updated) > 0 {
			fmt.Fprintln(w, "新内容在下一次连接或切场景时生效")
		}
	})
}
