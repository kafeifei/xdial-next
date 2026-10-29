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
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
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
	// Select switches a selector group to a member, 3.6.
	Select *SelectCommand `json:"select,omitempty"`
	// URLTest measures lines and the members of groups; the answer is a
	// status line carrying a TestResult with the same id, 3.6.
	URLTest *URLTestCommand `json:"url_test,omitempty"`
}

// SelectCommand switches Group to Member.
type SelectCommand struct {
	Group  string `json:"group"`
	Member string `json:"member"`
}

// URLTestCommand tests Tags: a line, or every member of a group.
type URLTestCommand struct {
	ID   int      `json:"id"`
	Tags []string `json:"tags"`
}

// testURL is what a test fetches through a line, sing-box's default.
const testURL = "https://www.gstatic.com/generate_204"

// testTimeout bounds one line's test.
const testTimeout = 10 * time.Second

func runCommand(ctx context.Context, instance *box.Box, r *reporter, c Command, stderr io.Writer) {
	switch {
	case c.Select != nil:
		o, ok := instance.Outbound().Outbound(c.Select.Group)
		selector, isSelector := o.(interface{ SelectOutbound(string) bool })
		if !ok || !isSelector || !selector.SelectOutbound(c.Select.Member) {
			fmt.Fprintln(stderr, "engine: select: cannot select", c.Select.Member, "in", c.Select.Group)
		}
		r.poke()
		return
	case c.URLTest != nil:
		_ = r.write(StatusLine{Test: &TestResult{ID: c.URLTest.ID, Results: urlTest(ctx, instance, r, c.URLTest.Tags)}})
		r.poke()
		return
	case c.TailscaleLogout == "":
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
	// The engine's own urltest history, so it can report what groups
	// measured; box.New uses it instead of making one.
	history := urltest.NewHistoryStorage()
	ctx = service.ContextWithPtr(ctx, history)
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
	// After the ready line, stdout carries status, 6.3.
	reports := newReporter(instance, history, stdout)
	go reports.run(ctx)
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
				runCommand(commandCtx, instance, reports, c, stderr)
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

// urlTest measures each tag: a group's members, or the line itself. Every
// result also goes into the history groups read, 3.6.
func urlTest(ctx context.Context, instance *box.Box, r *reporter, tags []string) map[string]TestOutcome {
	results := map[string]TestOutcome{}
	var test func(tag string, depth int)
	test = func(tag string, depth int) {
		if _, done := results[tag]; done {
			return
		}
		o, ok := instance.Outbound().Outbound(tag)
		if !ok {
			results[tag] = TestOutcome{Error: "没有这条线路"}
			return
		}
		if g, isGroup := o.(adapter.OutboundGroup); isGroup && depth < 4 {
			for _, member := range g.All() {
				test(member, depth+1)
			}
			return
		}
		testCtx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()
		delay, err := urltest.URLTest(testCtx, testURL, o)
		if err != nil {
			results[tag] = TestOutcome{Error: "测不通"}
			r.history.DeleteURLTestHistory(tag)
			return
		}
		results[tag] = TestOutcome{DelayMS: int(delay)}
		r.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
	}
	for _, tag := range tags {
		test(tag, 0)
	}
	return results
}
