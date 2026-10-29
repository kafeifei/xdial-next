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
	Hint    string `json:"hint,omitempty"` // printed when the error carries none
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
	CodeConfigMore           = "config.more"

	CodeDaemonUnreachable = "daemon.unreachable"
	CodeAPIPermission     = "api.permission"
	CodeAPIVersion        = "api.version"
	CodeConfigConflict    = "config.conflict"
	CodeSecretMissing     = "secret.missing"
	CodeSecretInUse       = "secret.in_use"
	CodeSecretFormat      = "secret.format"
	CodeEngineFailed      = "engine.failed"
	CodeDaemonUntrusted   = "daemon.untrusted"
	CodeDaemonBusy        = "daemon.busy"
	CodeEngineBusy        = "engine.busy"
	CodeConfirmRequired   = "api.confirm_required"
	CodeResourceMissing   = "resource.missing"
)

var codes = map[string]Code{}

func register(code Code) {
	if _, ok := codes[code.Name]; ok {
		panic("cli: error code registered twice: " + code.Name)
	}
	codes[code.Name] = code
}

func init() {
	register(Code{Name: CodeUsage, Exit: ExitUsage, Summary: "命令、参数或选项不对", Hint: "运行 xdial schema 查看全部命令"})
	register(Code{Name: CodeInputRead, Exit: ExitMissing, Summary: "读不到输入文件或 stdin：不存在、读出错", Hint: "确认文件存在、路径写对"})
	register(Code{Name: CodeInputPermission, Exit: ExitPermission, Summary: "没有权限读输入文件", Hint: "检查文件权限"})
	register(Code{Name: CodeConfigInvalid, Exit: ExitNegative, Summary: "配置有问题，详情在 problems", Hint: "按 problems 逐条修改后重新检查"})
	register(Code{Name: CodeConfigVersion, Exit: ExitNegative, Summary: "配置的 version 比这个 XDial 新", Hint: "升级 xdial"})
	register(Code{Name: CodeInternal, Exit: ExitInternal, Summary: "XDial 自己的错误", Hint: "这是缺陷，请附上命令和输出报告"})

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
	register(Code{Name: CodeConfigMore, Problem: true, Summary: "问题太多，只列出了前面的，这一条给出没列出的数量"})

	register(Code{Name: CodeDaemonUnreachable, Exit: ExitMissing, Summary: "daemon 没在运行，或者连不上 socket", Hint: "先运行 sudo xdial daemon install"})
	register(Code{Name: CodeDaemonUntrusted, Exit: ExitMissing, Summary: "socket 上监听的进程不属于 root，不是安装的 daemon；请求没有发出", Hint: "运行 sudo xdial daemon install 重新安装"})
	register(Code{Name: CodeDaemonBusy, Exit: ExitConflict, Summary: "daemon 的连接数已满", Hint: "关掉多余的 xdial logs --follow 后重试"})
	register(Code{Name: CodeAPIPermission, Exit: ExitPermission, Summary: "调用方不是 root，也不是当前在屏幕前登录的用户", Hint: "在屏幕前登录的账户里运行，或者加 sudo"})
	register(Code{Name: CodeAPIVersion, Exit: ExitMissing, Summary: "请求的协议版本 daemon 不认识", Hint: "用 sudo xdial daemon install 让 daemon 和 xdial 同一个版本"})
	register(Code{Name: CodeConfirmRequired, Exit: ExitPermission, Summary: "这次操作要先在本机上确认；第一版不产生", Hint: "按 message 的说明确认后重试"})
	register(Code{Name: CodeConfigConflict, Exit: ExitConflict, Summary: "配置已被别人改过，或者操作和当前状态冲突", Hint: "重新 export 后再改"})
	register(Code{Name: CodeSecretMissing, Exit: ExitMissing, Summary: "用到的凭据还没设置", Hint: "用 xdial secret set <名字> 设置"})
	register(Code{Name: CodeSecretInUse, Exit: ExitConflict, Summary: "凭据仍被引用，不能删除", Hint: "先改掉引用它的配置"})
	register(Code{Name: CodeSecretFormat, Exit: ExitNegative, Summary: "凭据的格式不符合引用它的字段", Hint: "按提示改正后重新设置"})
	register(Code{Name: CodeEngineFailed, Exit: ExitNegative, Summary: "没能连上：引擎没能启动、启动后很快退出，或者 DNS 没能接管", Hint: "用 xdial status 看原因"})
	register(Code{Name: CodeResourceMissing, Exit: ExitMissing, Summary: "场景用到的远程规则集或订阅还没下载", Hint: "等下载完成后再连接"})
	register(Code{Name: CodeEngineBusy, Exit: ExitConflict, Summary: "另一个 XDial 身份（正式版或 Debug）正连着", Hint: "先在另一个身份里 xdial disconnect"})
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
