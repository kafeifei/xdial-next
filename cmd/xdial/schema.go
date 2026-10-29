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

// endpointSchema is the status of one AnyConnect or Tailscale line.
func endpointSchema() map[string]any {
	return object([]string{"type", "state"}, map[string]any{
		"type":  map[string]any{"enum": []string{"openconnect", "tailscale"}},
		"state": map[string]any{"enum": []string{"connecting", "connected", "auth_required", "failed"}},
		"error": str(), "auth_message": str(), "browser_auth": map[string]any{"type": "boolean"},
		"addresses": strList(), "dns": strList(), "full_tunnel": map[string]any{"type": "boolean"}, "since": str(),
		"auth_url": str(), "tailnet": str(), "dns_name": str(), "exit_node": str(),
		"peers": map[string]any{"type": "integer"}, "online": map[string]any{"type": "integer"}, "self": strList(),
	})
}

func policySchema() map[string]any {
	return object([]string{"name", "rules"}, map[string]any{"name": str(), "rules": map[string]any{"type": "integer"}})
}

// secretRefSchema never has a value field: secrets are write-only.
func secretRefSchema() map[string]any {
	return object([]string{"name", "set", "references"}, map[string]any{
		"name": str(), "set": map[string]any{"type": "boolean"}, "updated": str(), "references": strList(),
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
		"xdial.daemon.install/v1": envelope("xdial.daemon.install/v1", object(
			[]string{"identity", "binary", "plist", "socket"},
			map[string]any{"identity": str(), "binary": str(), "plist": str(), "socket": str()},
		)),
		"xdial.daemon.uninstall/v1": envelope("xdial.daemon.uninstall/v1", object(
			[]string{"identity", "removed", "purged"},
			map[string]any{"identity": str(), "removed": strList(), "purged": map[string]any{"type": "boolean"}},
		)),
		"xdial.daemon.run/v1": envelope("xdial.daemon.run/v1", object([]string{"stopped"}, map[string]any{"stopped": map[string]any{"type": "boolean"}})),
		"xdial.status/v1": envelope("xdial.status/v1", object(
			[]string{"state", "connected", "scenario", "revision", "since", "last_error", "system_dns", "engine_pid"},
			map[string]any{
				"state":     map[string]any{"enum": []string{"disconnected", "connecting", "connected", "failed"}},
				"connected": map[string]any{"type": "boolean"}, "scenario": str(), "revision": str(), "since": str(),
				"last_error": str(), "system_dns": map[string]any{"type": "boolean"}, "engine_pid": map[string]any{"type": "integer"},
				"intent": map[string]any{"enum": []string{"connected", "disconnected"}}, "physical_dns": strList(),
				"endpoints": map[string]any{"type": "object", "additionalProperties": endpointSchema()},
			},
		)),
		"xdial.config.export/v1": envelope("xdial.config.export/v1", object(
			[]string{"revision", "content"}, map[string]any{"revision": str(), "content": map[string]any{"type": "object"}},
		)),
		"xdial.config.apply/v1": envelope("xdial.config.apply/v1", object(
			[]string{"applied", "revision", "previous_revision", "changes", "missing_secrets", "secrets", "pending", "reloaded"},
			map[string]any{
				"applied": map[string]any{"type": "boolean"}, "revision": str(), "previous_revision": str(),
				"changes": map[string]any{"type": "array", "items": object([]string{"kind", "id", "change"}, map[string]any{
					"kind": str(), "id": str(), "change": map[string]any{"enum": []string{"added", "removed", "changed"}},
				})},
				"missing_secrets": strList(), "secrets": map[string]any{"type": "array", "items": secretRefSchema()},
				"pending": strList(), "reloaded": map[string]any{"type": "boolean"},
			},
		)),
		"xdial.secret/v1":      envelope("xdial.secret/v1", secretRefSchema()),
		"xdial.secret.list/v1": envelope("xdial.secret.list/v1", object([]string{"secrets"}, map[string]any{"secrets": map[string]any{"type": "array", "items": secretRefSchema()}})),
		"xdial.rule-set.list/v1": envelope("xdial.rule-set.list/v1", object([]string{"rule_sets"}, map[string]any{
			"rule_sets": map[string]any{"type": "array", "items": object([]string{"id", "type", "cached", "rules"}, map[string]any{
				"id": str(), "name": str(), "type": map[string]any{"enum": []string{"inline", "remote"}},
				"format": str(), "download_via": str(), "cached": map[string]any{"type": "boolean"},
				"rules": map[string]any{"type": "integer"}, "fetched_at": str(), "changed_at": str(), "next_update": str(),
				"last_error": object([]string{"code", "message"}, map[string]any{"code": str(), "message": str(), "hint": str(),
					"problems": map[string]any{"type": "array"}}),
			})},
		})),
		"xdial.rule-set.update/v1": envelope("xdial.rule-set.update/v1", object([]string{"updated"}, map[string]any{
			"updated": map[string]any{"type": "array", "items": object([]string{"id", "changed", "rules", "fetched_at"}, map[string]any{
				"id": str(), "changed": map[string]any{"type": "boolean"}, "rules": map[string]any{"type": "integer"}, "fetched_at": str(),
			})},
		})),
		"xdial.subscription.list/v1": envelope("xdial.subscription.list/v1", object([]string{"subscriptions"}, map[string]any{
			"subscriptions": map[string]any{"type": "array", "items": object(
				[]string{"id", "download_via", "cached", "nodes", "rules", "policies", "unsupported"},
				map[string]any{
					"id": str(), "name": str(), "download_via": str(), "cached": map[string]any{"type": "boolean"}, "format": str(),
					"nodes": map[string]any{"type": "integer"}, "rules": map[string]any{"type": "integer"},
					"policies":    map[string]any{"type": "array", "items": policySchema()},
					"unsupported": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
					"fetched_at":  str(), "changed_at": str(), "next_update": str(),
					"last_error": object([]string{"code", "message"}, map[string]any{"code": str(), "message": str(), "hint": str(),
						"problems": map[string]any{"type": "array"}}),
				})},
		})),
		"xdial.subscription.show/v1": envelope("xdial.subscription.show/v1", object([]string{"id", "nodes", "policies"}, map[string]any{
			"id": str(),
			"nodes": map[string]any{"type": "array", "items": object([]string{"name", "type", "server", "server_port"}, map[string]any{
				"name": str(), "type": str(), "server": str(), "server_port": map[string]any{"type": "integer"},
			})},
			"policies": map[string]any{"type": "array", "items": policySchema()},
		})),
		"xdial.subscription.update/v1": envelope("xdial.subscription.update/v1", object([]string{"updated"}, map[string]any{
			"updated": map[string]any{"type": "array", "items": object([]string{"id", "changed", "nodes", "rules", "unsupported", "fetched_at"}, map[string]any{
				"id": str(), "changed": map[string]any{"type": "boolean"}, "nodes": map[string]any{"type": "integer"},
				"rules": map[string]any{"type": "integer"}, "fetched_at": str(),
				"unsupported": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
			})},
		})),
		"xdial.logs/v1": envelope("xdial.logs/v1", object([]string{"time", "type"}, map[string]any{
			"time": str(), "type": str(), "fields": map[string]any{"type": "object"},
		})),
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
