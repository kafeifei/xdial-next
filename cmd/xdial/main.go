// Command xdial is the XDial command line. It follows the conventions of
// ARCHITECTURE.md section 5: `xdial <noun> <verb>`, long options anywhere on
// the line, one JSON document on stdout with --json, registered error codes
// and the exit codes of 5.3.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/kafeifei/xdial-next/internal/buildinfo"
	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
)

func main() {
	if code, ok := hidden(os.Args[1:]); ok {
		os.Exit(code)
	}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// hidden runs the subcommands xdial starts itself: the one-shot check child
// and the engine child, ARCHITECTURE.md 2.2 and 6.1. They are not part of
// the CLI contract.
func hidden(args []string) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case engine.CheckCommand:
		return engine.RunCheckChild(os.Stdin, os.Stdout), true
	case engine.EngineCommand:
		return engine.RunEngineChild(os.Stdin, os.Stdout, os.Stderr, args[1:]), true
	}
	return 0, false
}

// command is one entry of the command table; `xdial schema` prints it.
type command struct {
	Path    []string `json:"command"`
	Args    []string `json:"args,omitempty"`
	Options []option `json:"options"`
	Summary string   `json:"summary"`
	Output  string   `json:"output_schema"`
	run     func(*context_) int
}

type option struct {
	Name    string `json:"name"`
	Value   string `json:"value,omitempty"`
	Summary string `json:"summary"`
}

var jsonOption = option{Name: "--json", Summary: "输出一个 JSON 文档，成功和失败都是"}

// context_ is what a command runs with.
type context_ struct {
	args    []string
	options map[string]string
	stdin   io.Reader
	out     cli.Output
}

func commands() []*command {
	return append([]*command{
		{
			Path: []string{"version"}, Summary: "显示这个 xdial 的版本", Output: versionSchema,
			Options: []option{jsonOption}, run: runVersion,
		},
		{
			Path: []string{"config", "check"}, Args: []string{"<文件>"}, Output: checkSchema,
			Summary: "离线检查一份配置：不联网、不依赖 daemon、不改任何状态（ARCHITECTURE.md 4.2）",
			Options: []option{jsonOption}, run: runConfigCheck,
		},
		{
			Path: []string{"schema"}, Summary: "列出全部命令、输出格式、错误码和配置格式", Output: schemaSchema,
			Options: []option{jsonOption}, run: runSchema,
		},
	}, daemonCommands()...)
}

const usageHint = "运行 xdial schema 查看全部命令"

// run executes one command line and returns the exit code. A panic is a
// defect: it is still reported in the output contract, as internal.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	// --json may stand anywhere before "--", the command words included.
	asJSON := false
	var rest []string
	for i, a := range args {
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		if a == "--json" {
			asJSON = true
			continue
		}
		rest = append(rest, a)
	}
	args = rest
	out := cli.Output{Stdout: stdout, Stderr: stderr, JSON: asJSON}
	defer func() {
		if r := recover(); r != nil {
			code = out.Fail(cli.Errorf(cli.CodeInternal, "", "xdial 内部错误：%v", r))
		}
	}()

	var words []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			break
		}
		words = append(words, a)
	}
	var cmd *command
	for _, c := range commands() {
		if len(words) >= len(c.Path) && equal(words[:len(c.Path)], c.Path) && (cmd == nil || len(c.Path) > len(cmd.Path)) {
			cmd = c
		}
	}
	if cmd == nil {
		if len(args) == 0 {
			return out.Fail(cli.Errorf(cli.CodeUsage, usageHint, "缺少命令"))
		}
		return out.Fail(cli.Errorf(cli.CodeUsage, usageHint, "不认识的命令 %q", strings.Join(words, " ")))
	}

	ctx := &context_{options: map[string]string{}, stdin: stdin, out: out}
	known, valued := map[string]bool{}, map[string]bool{}
	for _, o := range cmd.Options {
		if o.Name != "--json" {
			known[o.Name] = true
			valued[o.Name] = o.Value != ""
		}
	}
	rest = args[len(cmd.Path):]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			ctx.args = append(ctx.args, a)
			continue
		}
		if a == "--" {
			ctx.args = append(ctx.args, rest[i+1:]...)
			break
		}
		name, value, hasValue := strings.Cut(a, "=")
		if !strings.HasPrefix(name, "--") || !known[name] {
			return out.Fail(cli.Errorf(cli.CodeUsage, usageHint, "%s 不支持选项 %s", strings.Join(cmd.Path, " "), name))
		}
		if valued[name] && !hasValue {
			if i+1 >= len(rest) {
				return out.Fail(cli.Errorf(cli.CodeUsage, usageHint, "选项 %s 缺少值", name))
			}
			i++
			value = rest[i]
		} else if !valued[name] && hasValue {
			return out.Fail(cli.Errorf(cli.CodeUsage, usageHint, "选项 %s 不带值", name))
		}
		ctx.options[name] = value
	}
	if len(ctx.args) != len(cmd.Args) {
		return out.Fail(cli.Errorf(cli.CodeUsage, "用法：xdial "+strings.Join(append(append([]string{}, cmd.Path...), cmd.Args...), " "),
			"%s 需要 %d 个参数，这里有 %d 个", strings.Join(cmd.Path, " "), len(cmd.Args), len(ctx.args)))
	}
	return cmd.run(ctx)
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type versionInfo struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SingBox   string `json:"sing_box"`
}

func runVersion(ctx *context_) int {
	info := versionInfo{
		Version:   buildinfo.Version,
		Revision:  buildinfo.Revision(),
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		SingBox:   buildinfo.SingBox(),
	}
	return ctx.out.Succeed("xdial.version/v1", info, func(w io.Writer) {
		fmt.Fprintf(w, "xdial %s (%s, sing-box %s, %s, %s/%s)\n", info.Version, info.Revision, info.SingBox, info.GoVersion, info.OS, info.Arch)
	})
}

type secretReport struct {
	Name       string   `json:"name"`
	References []string `json:"references"`
}

type checkReport struct {
	Revision  string         `json:"revision"`
	Version   int            `json:"version"`
	Scenarios []string       `json:"scenarios"`
	Secrets   []secretReport `json:"secrets"`
	Pending   []string       `json:"pending"`
}

func runConfigCheck(ctx *context_) int {
	path := ctx.args[0]
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(ctx.stdin, config.MaxDocumentSize+1))
		if err != nil {
			err = cli.Errorf(cli.CodeInputRead, "", "读 stdin 出错：%v", err)
		}
	} else {
		data, err = readFile(path)
	}
	if err != nil {
		return ctx.out.Fail(err)
	}
	c, problems, err := config.Load(data)
	if errors.Is(err, config.ErrNewerVersion) {
		return ctx.out.Fail(cli.Errorf(cli.CodeConfigVersion, "升级 xdial 后再检查", "这份配置的 version 比这个 xdial 支持的 %d 新", config.CurrentVersion))
	}
	if err != nil {
		return ctx.out.Fail(err)
	}
	if len(problems) > 0 {
		return ctx.out.Fail(&cli.Error{Code: cli.CodeConfigInvalid, Message: fmt.Sprintf("配置有 %d 处问题", len(problems)), Hint: "按 problems 逐条修改后重新检查", Problems: problems})
	}

	exe, err := engine.Executable()
	if err != nil {
		return ctx.out.Fail(err)
	}
	report := checkReport{Revision: c.Root.Revision(), Version: c.Version, Scenarios: []string{}, Secrets: []secretReport{}, Pending: []string{}}
	for _, s := range c.Scenarios {
		report.Scenarios = append(report.Scenarios, s.ID)
	}
	verification, err := engine.Verify(context.Background(), exe, c)
	if err != nil {
		return ctx.out.Fail(cli.Errorf(cli.CodeInternal, "", "%v", err))
	}
	if len(verification.Problems) > 0 {
		return ctx.out.Fail(&cli.Error{Code: cli.CodeConfigInvalid, Message: fmt.Sprintf("配置有 %d 处问题", len(verification.Problems)), Problems: verification.Problems})
	}
	report.Pending = append(report.Pending, verification.Pending...)

	refs := map[string][]string{}
	for _, use := range c.Secrets {
		refs[use.Name] = append(refs[use.Name], use.Path)
	}
	for _, name := range sortedKeys(refs) {
		report.Secrets = append(report.Secrets, secretReport{Name: name, References: refs[name]})
	}
	if len(report.Secrets) > 0 {
		report.Pending = append(report.Pending, "凭据的真值不在离线检查的范围内，只用了占位值")
	}

	return ctx.out.Succeed("xdial.config.check/v1", report, func(w io.Writer) {
		fmt.Fprintf(w, "配置没有问题（revision %s）\n", report.Revision[:12])
		fmt.Fprintf(w, "场景：%s\n", cli.Escape(strings.Join(report.Scenarios, "、")))
		for _, s := range report.Secrets {
			fmt.Fprintf(w, "凭据 %s：%s\n", cli.Escape(s.Name), cli.Escape(strings.Join(s.References, "、")))
		}
		for _, p := range report.Pending {
			fmt.Fprintln(w, "没法离线验证：", cli.Escape(p))
		}
	})
}


// readFile reads the file the caller named, as the caller: the daemon never
// opens a path a caller supplies, ARCHITECTURE.md 4.1.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, cli.Errorf(cli.CodeInputPermission, "", "没有权限读 %s", path)
		}
		return nil, cli.Errorf(cli.CodeInputRead, "确认文件存在", "读不到 %s：%v", path, unwrapPathError(err))
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, config.MaxDocumentSize+1))
	if err != nil {
		return nil, cli.Errorf(cli.CodeInputRead, "", "读 %s 出错：%v", path, unwrapPathError(err))
	}
	return data, nil
}

func unwrapPathError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
