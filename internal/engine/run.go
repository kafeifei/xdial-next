package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/kafeifei/xdial-next/internal/buildinfo"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
)

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

// RunEngineChild reads one compiled configuration from stdin, starts it
// and runs until SIGTERM, SIGINT or the end of stdin. The daemon keeps
// stdin open for as long as it lives, so an engine whose daemon died, even
// by SIGKILL, shuts down instead of holding TUN, ARCHITECTURE.md 6.3.
// sing-box logs go to stderr, which the daemon scrubs. allowed are the only
// directories sing-box may touch.
func RunEngineChild(stdin io.Reader, stdout, stderr io.Writer, allowed []string) int {
	fail := func(stage string, err error) int {
		fmt.Fprintf(stderr, "engine: %s: %v\n", stage, err)
		_ = json.NewEncoder(stdout).Encode(Ready{Version: buildinfo.Build(), Error: stage + ": " + err.Error()})
		return 1
	}
	decoder := json.NewDecoder(io.LimitReader(stdin, 64<<20))
	var data json.RawMessage
	if err := decoder.Decode(&data); err != nil {
		return fail("read", err)
	}
	orphaned := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, io.MultiReader(decoder.Buffered(), stdin))
		close(orphaned)
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
	select {
	case <-signals:
	case <-orphaned:
		fmt.Fprintln(stderr, "engine: daemon went away, shutting down")
	}
	if err := instance.Close(); err != nil {
		fmt.Fprintln(stderr, "engine: close:", err)
		return 1
	}
	return 0
}
