package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
)

// EngineCommand is the hidden subcommand the daemon starts sing-box with,
// ARCHITECTURE.md 6.1: xdial __engine <allowed directory>...
const EngineCommand = "__engine"

// Ready is the line the engine prints once sing-box has started.
type Ready struct {
	Ready bool `json:"ready"`
	PID   int  `json:"pid"`
}

// RunEngineChild reads one compiled configuration from stdin, starts it
// and runs until SIGTERM, SIGINT or the end of stdin. The daemon keeps
// stdin open for as long as it lives, so an engine whose daemon died, even
// by SIGKILL, shuts down instead of holding TUN, ARCHITECTURE.md 6.3.
// sing-box logs go to stderr, which the daemon scrubs. allowed are the only
// directories sing-box may touch.
func RunEngineChild(stdin io.Reader, stdout, stderr io.Writer, allowed []string) int {
	decoder := json.NewDecoder(io.LimitReader(stdin, 64<<20))
	var data json.RawMessage
	if err := decoder.Decode(&data); err != nil {
		fmt.Fprintln(stderr, "engine: read:", err)
		return 1
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
		fmt.Fprintln(stderr, "engine: parse:", err)
		return 1
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		fmt.Fprintln(stderr, "engine: create:", err)
		return 1
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	if err := instance.Start(); err != nil {
		fmt.Fprintln(stderr, "engine: start:", err)
		_ = instance.Close()
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(Ready{Ready: true, PID: os.Getpid()}); err != nil {
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
