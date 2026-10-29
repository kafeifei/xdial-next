package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kafeifei/xdial-next/internal/api"
	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
	"github.com/kafeifei/xdial-next/internal/legacy"
)

const importSchema = "xdial.import.legacy/v1"

func importCommands() []*command {
	return []*command{{
		Path: []string{"import", "legacy"}, Output: importSchema, run: runImportLegacy,
		Summary: "导入旧版 XDial 的配置库：以你自己的身份读它和钥匙串里的密钥，转成新格式，配置走 apply、凭据走 secret set（ARCHITECTURE.md 4.8）。旧文件不动",
		Options: []option{jsonOption,
			{Name: "--dry-run", Summary: "只转换并报告能转什么、转不了什么，不连 daemon"},
			{Name: "--out", Value: "<文件>", Summary: "把转出的配置写到这个文件（不含凭据的值），方便先看"},
			{Name: "--replace", Summary: "daemon 里已经有配置时整份替换掉它"}},
	}}
}

// importResult is what import legacy prints.
type importResult struct {
	legacy.Report
	Applied  bool   `json:"applied"`
	Revision string `json:"revision,omitempty"`
}

func runImportLegacy(ctx *context_) int {
	// Root would read root's library and keychain, not the user's.
	if os.Geteuid() == 0 {
		return ctx.out.Fail(cli.Errorf(cli.CodeAPIPermission, "去掉 sudo，以你自己的身份运行", "旧配置库和它的密钥都是你的，不能用 root 读"))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInputRead, "", "找不到你的主目录：%v", err))
	}
	plain, err := legacy.Read(legacy.Path(home))
	if err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInputRead, "确认旧版 XDial 在这台 Mac 上用过，钥匙串弹窗选了允许", "%v", err))
	}
	result, err := legacy.Convert(plain)
	if err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeConfigInvalid, "", "%v", err))
	}
	// Only a new file: the old library, or anything else, is never written
	// over.
	if path := ctx.options["--out"]; path != "" {
		if err := writeNew(path, result.Config); err != nil {
			return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "换一个还不存在的文件", "写 %s 失败：%v", path, err))
		}
	}
	// The compile check config check runs: every scenario through sing-box,
	// with placeholders for secrets and for content not downloaded yet.
	if len(result.Report.Problems) == 0 {
		if err := verify(result); err != nil {
			return ctx.out.Fail(err)
		}
	}
	out := importResult{Report: result.Report}
	text := func(w io.Writer) { printImport(w, out) }
	if n := len(result.Report.Problems); n > 0 {
		problems := make([]cli.Problem, 0, n)
		for _, p := range result.Report.Problems {
			problems = append(problems, cli.Problem{Code: cli.CodeConfigValue, Path: p.What, Message: p.Why})
		}
		return ctx.out.Fail(&cli.Error{Code: cli.CodeConfigInvalid, Message: fmt.Sprintf("旧配置里有 %d 处转不了，没有导入", n),
			Hint: "按 problems 在旧版里改掉，或者等导入支持它们", Problems: problems})
	}
	if _, dry := ctx.options["--dry-run"]; dry {
		return ctx.out.Succeed(importSchema, out, text)
	}
	client, err := api.Dial(layout().Socket(), daemonUID)
	if err != nil {
		return ctx.out.Fail(err)
	}
	defer client.Close()
	// The configuration first: it may name secrets that are not set yet,
	// and nothing is set for a configuration that was not taken. Without
	// --replace the daemon takes it only while it has none, checked where
	// it writes.
	_, replace := ctx.options["--replace"]
	applied, err := once(client, "config.apply", map[string]any{"content": string(result.Config), "if_absent": !replace})
	if err != nil {
		var e *cli.Error
		if errors.As(err, &e) && e.Code == cli.CodeConfigConflict && !replace {
			e.Hint = "要整份替换就加 --replace"
		}
		return ctx.out.Fail(err)
	}
	out.Applied = true
	out.Revision, _ = applied["revision"].(string)
	for i, s := range result.Secrets {
		if _, err := once(client, "secret.set", map[string]any{"name": s.Name, "value": s.Value}); err != nil {
			return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "再运行一次 xdial import legacy --replace", "配置已经导入，第 %d 个凭据 %s 没存上：%v", i+1, s.Name, err))
		}
	}
	return ctx.out.Succeed(importSchema, out, text)
}

// once makes one call and returns its result object.
func once(client *api.Client, method string, params any) (map[string]any, error) {
	var result map[string]any
	var failure error
	err := client.Call(method, params, func(resp api.Response) bool {
		if !resp.OK {
			failure = resp.Error
			return false
		}
		failure = json.Unmarshal(resp.Result, &result)
		return false
	})
	if err != nil {
		return nil, err
	}
	return result, failure
}

func printImport(w io.Writer, r importResult) {
	if r.Applied {
		fmt.Fprintf(w, "已导入（revision %s）\n", short(r.Revision))
	} else {
		fmt.Fprintln(w, "没有导入，下面是报告")
	}
	fmt.Fprintf(w, "%d 份 Profile → %d 条线路、%d 个线路组、%d 个规则集、%d 个场景、%d 个凭据\n",
		r.Profiles, r.Lines, r.Groups, r.RuleSets, r.Scenarios, len(r.Secrets))
	if len(r.Problems) > 0 {
		fmt.Fprintln(w, "转不了：")
		for _, p := range r.Problems {
			fmt.Fprintln(w, cli.Escape("  "+p.What+"："+p.Why))
		}
	}
	if len(r.LeftOut) > 0 {
		fmt.Fprintln(w, "不迁移：")
		for _, p := range r.LeftOut {
			fmt.Fprintln(w, cli.Escape("  "+p.What+"："+p.Why))
		}
	}
}

// verify runs the compile check on the converted configuration and adds
// what it finds to the report's problems.
func verify(result *legacy.Result) error {
	c, _, err := config.Load(result.Config)
	if err != nil {
		return err
	}
	exe, err := engine.Executable()
	if err != nil {
		return err
	}
	verification, err := engine.Verify(context.Background(), exe, c)
	if err != nil {
		return cli.Errorf(cli.CodeInternal, "", "%v", err)
	}
	for _, p := range verification.Problems {
		result.Report.Problems = append(result.Report.Problems, legacy.Item{What: "转出的配置 " + p.Path, Why: p.Message})
	}
	return nil
}

// writeNew writes data to path, which must not exist yet.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
