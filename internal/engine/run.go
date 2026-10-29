package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kafeifei/xdial-next/internal/buildinfo"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

// MaxConfigSize is the most the engine reads from stdin. The daemon checks
// a compiled configuration against it before replacing a connection.
const MaxConfigSize = 64 << 20

// EngineCommand is the hidden subcommand the daemon starts sing-box with,
// ARCHITECTURE.md 6.1: xdial __engine <allowed directory>...
const EngineCommand = "__engine"

// Ready is the one line the engine prints on stdout, ARCHITECTURE.md 6.3:
// ready once sing-box has started, or why it could not. Version lets the
// daemon refuse an engine binary that is not its own build.
type Ready struct {
	Ready   bool   `json:"ready"`
	PID     int    `json:"pid,omitempty"`
	Version string `json:"version"`
	Error   string `json:"error,omitempty"`
}

// Command is a line the daemon writes to the engine's stdin after the
// configuration, ARCHITECTURE.md 6.3. The engine answers through the
// status lines it writes anyway.
type Command struct {
	// TailscaleLogout logs the tailscale line with this id out; it then
	// waits for a new login, 3.5.
	TailscaleLogout string `json:"tailscale_logout,omitempty"`
}

func runCommand(ctx context.Context, instance *box.Box, c Command, stderr io.Writer) {
	if c.TailscaleLogout == "" {
		return
	}
	e, ok := instance.Endpoint().Get(c.TailscaleLogout)
	ts, isTailscale := e.(adapter.TailscaleEndpoint)
	if !ok || !isTailscale {
		fmt.Fprintln(stderr, "engine: logout: no tailscale line", c.TailscaleLogout)
		return
	}
	logoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ts.Logout(logoutCtx); err != nil {
		fmt.Fprintln(stderr, "engine: logout:", err)
	}
}

// RunEngineChild reads one compiled configuration from stdin, starts it
// and runs until SIGTERM, SIGINT or the end of stdin. The daemon keeps
// stdin open for as long as it lives, so an engine whose daemon died, even
// by SIGKILL, shuts down instead of holding TUN, ARCHITECTURE.md 6.3.
// sing-box logs go to stderr, which the daemon scrubs. allowed are the only
// directories sing-box may touch.
func RunEngineChild(stdin io.Reader, stdout, stderr io.Writer, allowed []string) int {
	// fd 3 is the connection lock the daemon passes down, ARCHITECTURE.md
	// 6.1. The engine holds it by keeping it open; what sing-box starts,
	// such as dscacheutil when TUN closes, must not inherit it, or the lock
	// would outlive the engine.
	syscall.CloseOnExec(3)
	fail := func(stage string, err error) int {
		fmt.Fprintf(stderr, "engine: %s: %v\n", stage, err)
		_ = json.NewEncoder(stdout).Encode(Ready{Version: buildinfo.Build(), Error: stage + ": " + err.Error()})
		return 1
	}
	decoder := json.NewDecoder(io.LimitReader(stdin, MaxConfigSize))
	var data json.RawMessage
	if err := decoder.Decode(&data); err != nil {
		return fail("read", err)
	}
	// After the configuration, stdin carries commands, one JSON value
	// each, until the daemon goes away, 6.3.
	orphaned := make(chan struct{})
	commands := make(chan Command, 8)
	go func() {
		defer close(orphaned)
		in := json.NewDecoder(io.MultiReader(decoder.Buffered(), stdin))
		for {
			var c Command
			if err := in.Decode(&c); err != nil {
				_, _ = io.Copy(io.Discard, stdin)
				return
			}
			select {
			case commands <- c:
			default:
				fmt.Fprintln(stderr, "engine: command dropped, too many pending")
			}
		}
	}()
	ctx, cancel := context.WithCancel(Context(context.Background(), allowed...))
	defer cancel()
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, data); err != nil {
		return fail("parse", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return fail("create", err)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return fail("start", err)
	}
	if err := json.NewEncoder(stdout).Encode(Ready{Ready: true, PID: os.Getpid(), Version: buildinfo.Build()}); err != nil {
		_ = instance.Close()
		return 1
	}
	// After the ready line, stdout carries endpoint status, 6.3.
	go reportEndpoints(ctx, instance, stdout)
	// Commands run one at a time in a worker of their own: a logout can
	// wait on the control server, and the loop below must stay free for
	// the signals and the daemon going away. Leaving cancels the command.
	commandCtx, stopCommands := context.WithCancel(ctx)
	go func() {
		for {
			select {
			case <-commandCtx.Done():
				return
			case c := <-commands:
				runCommand(commandCtx, instance, c, stderr)
			}
		}
	}()
	select {
	case <-signals:
	case <-orphaned:
		fmt.Fprintln(stderr, "engine: daemon went away, shutting down")
	}
	stopCommands()
	if err := instance.Close(); err != nil {
		fmt.Fprintln(stderr, "engine: close:", err)
		return 1
	}
	return 0
}
