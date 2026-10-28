// Package daemon is `xdial daemon`, ARCHITECTURE.md section 6: it holds the
// configuration, credentials and state, serves the local API, supervises the
// engine child and points the system resolver into TUN while connected.
package daemon

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/paths"
	"github.com/kafeifei/xdial-next/internal/store"
	"github.com/kafeifei/xdial-next/internal/sysdns"
)

// Options configures a daemon. Tests replace the system hooks.
type Options struct {
	Layout paths.Layout
	// Executable starts the engine and the checks; the daemon runs its own
	// root-owned copy, 6.1.
	Executable string
	// Authorize decides whether a peer may use the API; nil means root or a
	// member of admin, 6.2.
	Authorize func(uid uint32, groups []uint32) bool
	// SetDNS and ClearDNS manage the system resolver key, 6.4.
	SetDNS   func(key string, server netip.Addr) error
	ClearDNS func(key string) error
	// ExcludeFromBackup marks a directory for Time Machine to skip, 4.4.
	ExcludeFromBackup func(dir string) error
	// NoTUN leaves the TUN inbound out, so tests run the engine unprivileged.
	NoTUN bool
}

// adminGroup is the gid of macOS's admin group.
const adminGroup = 80

func defaultAuthorize(uid uint32, groups []uint32) bool {
	if uid == 0 {
		return true
	}
	for _, g := range groups {
		if g == adminGroup {
			return true
		}
	}
	return false
}

func excludeFromBackup(dir string) error {
	return exec.Command("/usr/bin/tmutil", "addexclusion", dir).Run()
}

// State is what survives a restart besides the configuration, 4.1.
type State struct {
	Scenario  string `json:"scenario,omitempty"`
	Connected bool   `json:"connected"`
}

// Secret is one stored credential, 4.4.
type Secret struct {
	Value   string    `json:"value"`
	Updated time.Time `json:"updated"`
}

// Daemon is one running daemon.
type Daemon struct {
	opts   Options
	events *eventLog

	mu       sync.Mutex
	raw      []byte // the stored canonical configuration
	cfg      *config.Config
	state    State
	secrets  map[string]Secret
	engine   *engineProc
	status   string // disconnected, connecting, connected, failed
	since    time.Time
	lastErr  string
	dnsSet   bool
	failures []time.Time
	closing  bool
}

// New prepares a daemon: directories, permissions, stored files. It also
// clears a resolver key a killed predecessor may have left, 6.3.
func New(opts Options) (*Daemon, error) {
	if opts.Authorize == nil {
		opts.Authorize = defaultAuthorize
	}
	if opts.SetDNS == nil {
		opts.SetDNS = sysdns.Set
	}
	if opts.ClearDNS == nil {
		opts.ClearDNS = sysdns.Clear
	}
	if opts.ExcludeFromBackup == nil {
		opts.ExcludeFromBackup = excludeFromBackup
	}
	l := opts.Layout
	for _, d := range []struct {
		path string
		perm os.FileMode
	}{{l.Data(), 0o755}, {l.Private(), 0o700}, {l.Tailscale(), 0o700}} {
		if err := store.EnsureDir(d.path, d.perm); err != nil {
			return nil, err
		}
	}
	d := &Daemon{opts: opts, status: "disconnected", since: time.Now(), secrets: map[string]Secret{}}
	d.events = newEventLog(l.Events())
	if err := opts.ExcludeFromBackup(l.Private()); err != nil {
		d.events.add("backup_exclusion_failed", map[string]any{"error": err.Error()})
	}
	if err := opts.ClearDNS(l.DNSKey()); err != nil {
		d.events.add("dns_clear_failed", map[string]any{"error": err.Error()})
	}
	if err := store.ReadJSON(l.State(), &d.state); err != nil {
		return nil, err
	}
	if err := store.ReadJSON(l.Secrets(), &d.secrets); err != nil {
		return nil, err
	}
	if raw, err := os.ReadFile(l.Config()); err == nil {
		c, problems, err := config.Load(raw)
		if err != nil || len(problems) > 0 {
			// A stored configuration that no longer loads stays on disk
			// for export, but nothing runs from it.
			d.events.add("config_unloadable", map[string]any{"problems": len(problems)})
		} else {
			d.raw, d.cfg = raw, c
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return d, nil
}

// Run serves the local API until ctx ends, resuming a connection the state
// says was up. On the way out it disconnects without changing the desired
// state, so the next start resumes it.
func (d *Daemon) Run(ctx context.Context) error {
	listener, err := d.listen()
	if err != nil {
		return err
	}
	d.events.add("daemon_started", nil)
	d.mu.Lock()
	if d.state.Connected && d.cfg != nil {
		if err := d.connectLocked(d.state.Scenario); err != nil {
			d.lastErr = err.Error()
		}
	}
	d.mu.Unlock()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	err = d.serve(listener)
	d.mu.Lock()
	d.closing = true
	d.teardownLocked()
	d.mu.Unlock()
	d.events.add("daemon_stopped", nil)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (d *Daemon) saveState() error {
	return store.WriteJSON(d.opts.Layout.State(), d.state, 0o600)
}

func (d *Daemon) saveSecrets() error {
	return store.WriteJSON(d.opts.Layout.Secrets(), d.secrets, 0o600)
}

func (d *Daemon) revision() string {
	if d.cfg == nil {
		return ""
	}
	return d.cfg.Root.Revision()
}

func (d *Daemon) setStatus(status, lastErr string) {
	d.status = status
	d.since = time.Now()
	d.lastErr = lastErr
}
