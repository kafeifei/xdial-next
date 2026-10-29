package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
)

// CheckCommand is the hidden subcommand the one-shot check child runs.
const CheckCommand = "__engine-check"

// checkTimeout bounds the child: box.New only constructs, it never connects.
const checkTimeout = 30 * time.Second

// maxReport bounds what the parent reads back from the child.
const maxReport = 64 << 10

type report struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// CheckInProcess parses a compiled configuration with the restricted
// registry, constructs it with box.New and closes it again, which is what
// `sing-box check` does. sing-box can panic while constructing, so this
// runs only in a one-shot child, ARCHITECTURE.md 2.2.
func CheckInProcess(compiled []byte) error {
	ctx, cancel := context.WithCancel(Context(context.Background()))
	defer cancel()
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, compiled); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return err
	}
	return instance.Close()
}

// RunCheckChild is the body of the hidden subcommand: it reads a compiled
// configuration from stdin and prints one JSON report.
func RunCheckChild(stdin io.Reader, stdout io.Writer) int {
	data, err := io.ReadAll(io.LimitReader(stdin, MaxConfigSize))
	r := report{OK: true}
	if err == nil {
		err = CheckInProcess(data)
	}
	if err != nil {
		r = report{Error: err.Error()}
	}
	_ = json.NewEncoder(stdout).Encode(r)
	if !r.OK {
		return 1
	}
	return 0
}

// ErrCheckUnavailable means the check child could not run at all. That is
// XDial's own failure, not a problem in the configuration.
var ErrCheckUnavailable = errors.New("sing-box 检查进程起不来")

// Check runs CheckInProcess in a one-shot child of executable, so a panic in
// sing-box takes down the child and not the caller. The configuration it
// checks holds placeholders, never real secrets. Any error other than
// ErrCheckUnavailable is the configuration's.
func Check(ctx context.Context, executable string, compiled []byte) error {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, CheckCommand)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	return CheckWith(ctx, cmd, compiled)
}

// CheckWith is Check with a command the caller prepared, for example to run
// the child as another user. cmd must run CheckCommand and be bound to ctx.
func CheckWith(ctx context.Context, cmd *exec.Cmd, compiled []byte) error {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	cmd.Stdin = bytes.NewReader(compiled)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: maxReport}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w：%v", ErrCheckUnavailable, err)
	}
	runErr := cmd.Wait()
	var r report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("sing-box 检查超过 %s 没有结束，配置可能太大或太复杂", checkTimeout)
		}
		return fmt.Errorf("sing-box 检查进程异常退出：%s", panicLine(stderr.String()))
	}
	if r.OK && runErr == nil {
		return nil
	}
	if r.Error == "" {
		return fmt.Errorf("sing-box 检查进程异常退出：%s", panicLine(stderr.String()))
	}
	return errors.New(r.Error)
}

// panicLine picks the line that says what went wrong out of a crash's
// stderr, so the problem points somewhere without dumping a stack.
func panicLine(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "panic:") || strings.HasPrefix(line, "fatal error:") {
			if len(line) > 200 {
				line = line[:200]
			}
			return line
		}
	}
	return "没有输出原因"
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > l.n {
		p = p[:l.n]
	}
	l.n -= len(p)
	if len(p) > 0 {
		if _, err := l.w.Write(p); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// Executable is the path of the running binary, used to start the child.
func Executable() (string, error) { return os.Executable() }
