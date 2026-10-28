package main

import (
	"fmt"
	"io"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
)

// Output schemas, ARCHITECTURE.md 5.2. Within one version fields are only
// added; renaming, removing or retyping one needs a new version.
const (
	versionSchema = "xdial.version/v1"
	checkSchema   = "xdial.config.check/v1"
	schemaSchema  = "xdial.schema/v1"
)

func str() map[string]any { return map[string]any{"type": "string"} }

func strList() map[string]any { return map[string]any{"type": "array", "items": str()} }

func object(required []string, props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

// envelope wraps a result schema the way cli.Output prints it.
func envelope(name string, result map[string]any) map[string]any {
	return object([]string{"schema", "ok", "result"}, map[string]any{
		"schema": map[string]any{"const": name},
		"ok":     map[string]any{"const": true},
		"result": result,
	})
}

func outputSchemas() map[string]any {
	problem := object([]string{"code", "message"}, map[string]any{
		"code": str(), "path": str(), "object": str(), "message": str(), "hint": str(),
	})
	return map[string]any{
		versionSchema: envelope(versionSchema, object(
			[]string{"version", "revision", "go_version", "os", "arch", "sing_box"},
			map[string]any{"version": str(), "revision": str(), "go_version": str(), "os": str(), "arch": str(), "sing_box": str()},
		)),
		checkSchema: envelope(checkSchema, object(
			[]string{"revision", "version", "scenarios", "secrets", "pending"},
			map[string]any{
				"revision":  str(),
				"version":   map[string]any{"type": "integer"},
				"scenarios": strList(),
				"secrets": map[string]any{"type": "array", "items": object([]string{"name", "references"}, map[string]any{
					"name": str(), "references": strList(),
				})},
				"pending": strList(),
			},
		)),
		schemaSchema: envelope(schemaSchema, object(
			[]string{"commands", "errors", "exit_codes", "outputs", "config"},
			map[string]any{
				"commands":   map[string]any{"type": "array"},
				"errors":     map[string]any{"type": "array"},
				"exit_codes": map[string]any{"type": "array"},
				"outputs":    map[string]any{"type": "object"},
				"config":     map[string]any{"type": "object"},
			},
		)),
		cli.ErrorSchema: object([]string{"schema", "ok", "error"}, map[string]any{
			"schema": map[string]any{"const": cli.ErrorSchema},
			"ok":     map[string]any{"const": false},
			"error": object([]string{"code", "message"}, map[string]any{
				"code": str(), "message": str(), "hint": str(),
				"problems": map[string]any{"type": "array", "items": problem},
			}),
		}),
	}
}

type exitCode struct {
	Code    int    `json:"code"`
	Summary string `json:"summary"`
}

var exitCodes = []exitCode{
	{cli.ExitOK, "成功"},
	{cli.ExitNegative, "命令跑完了，结论是否定的，例如检查发现问题"},
	{cli.ExitUsage, "用法错误：命令、参数或选项不对"},
	{cli.ExitMissing, "依赖的东西不在：daemon 没在运行、文件不存在、资源还没下载"},
	{cli.ExitPermission, "没有权限"},
	{cli.ExitConflict, "冲突：--if-match 的 revision 已经过时，或者操作和当前状态冲突"},
	{cli.ExitInternal, "XDial 自己的错误（缺陷）"},
}

type schemaReport struct {
	Commands  []*command     `json:"commands"`
	Errors    []cli.Code     `json:"errors"`
	ExitCodes []exitCode     `json:"exit_codes"`
	Outputs   map[string]any `json:"outputs"`
	Config    map[string]any `json:"config"`
}

func runSchema(ctx *context_) int {
	report := schemaReport{
		Commands:  commands(),
		Errors:    cli.Codes(),
		ExitCodes: exitCodes,
		Outputs:   outputSchemas(),
		Config:    config.JSONSchema(),
	}
	return ctx.out.Succeed(schemaSchema, report, func(w io.Writer) {
		fmt.Fprintln(w, "命令：")
		for _, c := range report.Commands {
			fmt.Fprintf(w, "  xdial %s", joinWords(c.Path))
			for _, a := range c.Args {
				fmt.Fprintf(w, " %s", a)
			}
			fmt.Fprintf(w, "\n      %s\n", c.Summary)
		}
		fmt.Fprintln(w, "错误码：")
		for _, c := range report.Errors {
			fmt.Fprintf(w, "  %-26s %s\n", c.Name, c.Summary)
		}
		fmt.Fprintln(w, "退出码：")
		for _, e := range report.ExitCodes {
			fmt.Fprintf(w, "  %-3d %s\n", e.Code, e.Summary)
		}
		fmt.Fprintln(w, "完整的输出格式和配置格式见 xdial schema --json")
	})
}

func joinWords(words []string) string {
	out := ""
	for i, w := range words {
		if i > 0 {
			out += " "
		}
		out += w
	}
	return out
}
