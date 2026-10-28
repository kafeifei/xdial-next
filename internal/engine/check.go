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
	data, err := io.ReadAll(io.LimitReader(stdin, 64<<20))
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

// ErrCheckCrashed is a child that died without a report, as when sing-box
// panics on something the value checks let through.
var ErrCheckCrashed = errors.New("sing-box 检查进程异常退出")

// Check runs CheckInProcess in a one-shot child of executable, so a panic in
// sing-box takes down the child and not the caller. The configuration it
// checks holds placeholders, never real secrets.
func Check(ctx context.Context, executable string, compiled []byte) error {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, CheckCommand)
	cmd.Stdin = bytes.NewReader(compiled)
	var stdout bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: maxReport}
	cmd.Stderr = io.Discard
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	runErr := cmd.Run()
	var r report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("sing-box 检查超过 %s 没有结束", checkTimeout)
		}
		return ErrCheckCrashed
	}
	if r.OK && runErr == nil {
		return nil
	}
	if r.Error == "" {
		return ErrCheckCrashed
	}
	return errors.New(r.Error)
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
