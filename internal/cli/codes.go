// Package cli holds the conventions every xdial command follows: the JSON
// envelope, the registered error codes, exit codes and how external text is
// printed. ARCHITECTURE.md section 5 is the contract; this package is the
// only place that writes to stdout and stderr on a command's behalf.
package cli

import "sort"

// Exit codes, ARCHITECTURE.md 5.3.
const (
	ExitOK         = 0
	ExitNegative   = 1
	ExitUsage      = 2
	ExitMissing    = 3
	ExitPermission = 4
	ExitConflict   = 5
	ExitInternal   = 70
)

// Code describes one registered error code. Problem codes appear only inside
// the problems of an error and carry no exit code of their own.
type Code struct {
	Name    string `json:"code"`
	Exit    int    `json:"exit,omitempty"`
	Problem bool   `json:"problem,omitempty"`
	Summary string `json:"summary"`
}

// Error codes, ARCHITECTURE.md 5.4. A code is never renamed or reused; a
// retired one stays here so its name cannot come back with a new meaning.
const (
	CodeUsage           = "usage"
	CodeInputRead       = "input.read"
	CodeInputPermission = "input.permission"
	CodeConfigInvalid   = "config.invalid"
	CodeConfigVersion   = "config.version"
	CodeInternal        = "internal"

	CodeConfigSyntax         = "config.syntax"
	CodeConfigUnknownKey     = "config.unknown_key"
	CodeConfigDuplicateKey   = "config.duplicate_key"
	CodeConfigForbiddenKey   = "config.forbidden_key"
	CodeConfigSecretInline   = "config.secret_inline"
	CodeConfigValue          = "config.value"
	CodeConfigTypeNotAllowed = "config.type_not_allowed"
	CodeConfigReference      = "config.reference"
	CodeConfigCycle          = "config.cycle"
	CodeConfigDuplicateID    = "config.duplicate_id"
	CodeConfigCompile        = "config.compile"
)

var codes = map[string]Code{}

func register(code Code) {
	if _, ok := codes[code.Name]; ok {
		panic("cli: error code registered twice: " + code.Name)
	}
	codes[code.Name] = code
}

func init() {
	register(Code{Name: CodeUsage, Exit: ExitUsage, Summary: "命令、参数或选项不对"})
	register(Code{Name: CodeInputRead, Exit: ExitMissing, Summary: "读不到输入文件或 stdin：不存在、读出错"})
	register(Code{Name: CodeInputPermission, Exit: ExitPermission, Summary: "没有权限读输入文件"})
	register(Code{Name: CodeConfigInvalid, Exit: ExitNegative, Summary: "配置有问题，详情在 problems"})
	register(Code{Name: CodeConfigVersion, Exit: ExitNegative, Summary: "配置的 version 比这个 XDial 新"})
	register(Code{Name: CodeInternal, Exit: ExitInternal, Summary: "XDial 自己的错误"})

	register(Code{Name: CodeConfigSyntax, Problem: true, Summary: "JSON 语法错误"})
	register(Code{Name: CodeConfigUnknownKey, Problem: true, Summary: "没有登记的键，或者大小写不一致"})
	register(Code{Name: CodeConfigDuplicateKey, Problem: true, Summary: "同一个对象里键重复"})
	register(Code{Name: CodeConfigForbiddenKey, Problem: true, Summary: "禁止类或 XDial 生成类的键"})
	register(Code{Name: CodeConfigSecretInline, Problem: true, Summary: "凭据字段写了明文"})
	register(Code{Name: CodeConfigValue, Problem: true, Summary: "值不在值域里"})
	register(Code{Name: CodeConfigTypeNotAllowed, Problem: true, Summary: "类型不在允许清单里"})
	register(Code{Name: CodeConfigReference, Problem: true, Summary: "引用的对象不存在，或者类别不对"})
	register(Code{Name: CodeConfigCycle, Problem: true, Summary: "detour 和组成员成环"})
	register(Code{Name: CodeConfigDuplicateID, Problem: true, Summary: "id 重复"})
	register(Code{Name: CodeConfigCompile, Problem: true, Summary: "编译出的 sing-box 配置没通过检查"})
}

// Lookup returns the registration of a code.
func Lookup(name string) (Code, bool) {
	code, ok := codes[name]
	return code, ok
}

// Codes returns every registered code, sorted by name.
func Codes() []Code {
	list := make([]Code, 0, len(codes))
	for _, code := range codes {
		list = append(list, code)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}
