package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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

// layoutRoot prefixes every daemon path; only tests set it.
var layoutRoot string

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
	client, err := api.Dial(layout().Socket())
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
// is booted out first, so this also upgrades.
func runDaemonInstall(ctx *context_) int {
	if err := requireRoot(); err != nil {
		return ctx.out.Fail(err)
	}
	l := layout()
	exe, err := os.Executable()
	if err != nil {
		return ctx.out.Fail(err)
	}
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+l.ID).Run()
	for _, dir := range []string{l.Data(), filepath.Dir(l.Bin())} {
		if err := store.EnsureDir(dir, 0o755); err != nil {
			return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "建目录 %s 失败：%v", dir, err))
		}
		if err := os.Chown(dir, 0, 0); err != nil {
			return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "%v", err))
		}
	}
	if err := store.EnsureDir(l.Private(), 0o700); err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "%v", err))
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInputRead, "", "读 %s 出错：%v", exe, err))
	}
	if err := store.WriteFile(l.Bin(), binary, 0o755); err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "拷贝二进制失败：%v", err))
	}
	plist := fmt.Sprintf(plistTemplate, l.ID, l.Bin(), l.DaemonLog(), l.DaemonLog())
	if err := store.EnsureDir(filepath.Dir(l.Plist()), 0o755); err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "%v", err))
	}
	if err := store.WriteFile(l.Plist(), []byte(plist), 0o644); err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "写 launchd 配置失败：%v", err))
	}
	if out, err := exec.Command("/bin/launchctl", "bootstrap", "system", l.Plist()).CombinedOutput(); err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "launchctl bootstrap 失败：%v：%s", err, strings.TrimSpace(string(out))))
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if c, err := api.Dial(l.Socket()); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			return ctx.out.Fail(cli.Errorf(cli.CodeDaemonUnreachable, "看 "+l.DaemonLog(), "daemon 装好了，但 15 秒内没有起来"))
		}
		time.Sleep(200 * time.Millisecond)
	}
	report := installReport{Identity: l.ID, Binary: l.Bin(), Plist: l.Plist(), Socket: l.Socket()}
	return ctx.out.Succeed("xdial.daemon.install/v1", report, func(w io.Writer) {
		fmt.Fprintf(w, "daemon %s 已安装并启动\n", l.ID)
	})
}

// runDaemonUninstall boots the daemon out, which makes it disconnect, then
// removes what install put down; --purge removes the data too, 6.1.
func runDaemonUninstall(ctx *context_) int {
	if err := requireRoot(); err != nil {
		return ctx.out.Fail(err)
	}
	l := layout()
	_ = exec.Command("/bin/launchctl", "bootout", "system/"+l.ID).Run()
	// The daemon clears its resolver when it stops; clear it again in case
	// it was not running to do so.
	_ = sysdns.Clear(l.DNSKey())
	_, purge := ctx.options["--purge"]
	removed := []string{}
	targets := []string{l.Plist(), filepath.Dir(l.Bin()), l.SocketDir()}
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
