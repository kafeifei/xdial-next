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
	"syscall"
	"time"

	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/paths"
	"github.com/kafeifei/xdial-next/internal/store"
)

// Options configures a daemon. Tests replace the system hooks.
type Options struct {
	Layout paths.Layout
	// Executable starts the engine and the checks; the daemon runs its own
	// root-owned copy, 6.1.
	Executable string
	// Authorize decides whether a peer may use the API; nil means root or
	// the user logged in at the console, 6.2.
	Authorize func(uid uint32) bool
	// System reaches macOS for DNS, 6.4; nil means the real one.
	System System
	// ExcludeFromBackup marks a directory for Time Machine to skip, 4.4.
	ExcludeFromBackup func(dir string) error
	// NoTUN leaves the TUN inbound out, so tests run the engine unprivileged.
	NoTUN bool
}

// consoleOrRoot allows root and the user logged in at the console: the
// owner of /dev/console, which is root at the login window. It is asked on
// every request, so after a fast user switch the previous user is refused.
func consoleOrRoot(uid uint32) bool {
	if uid == 0 {
		return true
	}
	info, err := os.Stat("/dev/console")
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid
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
	sys    System
	events *eventLog

	// ctl serializes everything that starts, stops or replaces the
	// connection, 6.3. mu guards the fields below and is never held across
	// a slow step, so status answers while a connection is coming up.
	ctl sync.Mutex
	mu  sync.Mutex

	raw      []byte // the stored canonical configuration
	cfg      *config.Config
	state    State // what the user asked for; persisted
	secrets  map[string]Secret
	conn     *connection
	status   string // disconnected, connecting, connected, failed
	since    time.Time
	lastErr  string
	physical []netip.Addr // the physical DNS of the last attempt
	gen      uint64       // bumped by every request that changes the connection
	failures []time.Time
	closing  bool
	// wake tells monitor the connection changed, so it watches the new
	// resolver session.
	wake chan struct{}
}

// New prepares a daemon: directories, permissions, stored files. It also
// removes a resolver key an older build may have left; the key this build
// sets goes by itself with the session holding it, 6.4.
func New(opts Options) (*Daemon, error) {
	if opts.Authorize == nil {
		opts.Authorize = consoleOrRoot
	}
	if opts.System == nil {
		opts.System = macOS{}
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
	trimDaemonLog(l.DaemonLog())
	d := &Daemon{opts: opts, sys: opts.System, status: "disconnected", since: time.Now(), secrets: map[string]Secret{}, wake: make(chan struct{}, 1)}
	d.events = newEventLog(l.Events())
	if err := opts.ExcludeFromBackup(l.Private()); err != nil {
		d.events.add("backup_exclusion_failed", map[string]any{"error": err.Error()})
	}
	if err := d.sys.ClearStale(l.DNSKey()); err != nil {
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
// says the user wants. On the way out it disconnects without changing that
// state, so the next start resumes it.
func (d *Daemon) Run(ctx context.Context) error {
	listener, err := d.listen()
	if err != nil {
		return err
	}
	d.events.add("daemon_started", nil)
	d.ctl.Lock()
	d.mu.Lock()
	resume := d.state.Connected
	d.mu.Unlock()
	if resume {
		if err := d.establishLocked(); err != nil {
			d.retryLocked(err.Error())
		}
	}
	d.ctl.Unlock()
	monitorDone := make(chan struct{})
	go func() {
		d.monitor(ctx)
		close(monitorDone)
	}()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	err = d.serve(listener)
	<-monitorDone
	d.ctl.Lock()
	d.mu.Lock()
	d.closing = true
	d.mu.Unlock()
	d.disconnectLocked()
	d.ctl.Unlock()
	d.events.add("daemon_stopped", nil)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// monitor calls reconcile on every change the resolver session reports,
// once the burst settles, and every checkInterval.
func (d *Daemon) monitor(ctx context.Context) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		var changes, done <-chan struct{}
		d.mu.Lock()
		if d.conn != nil && d.conn.resolver != nil {
			changes, done = d.conn.resolver.Changes(), d.conn.resolver.Done()
		}
		d.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-d.wake:
			continue
		case <-ticker.C:
		case <-done:
		case <-changes:
			select {
			case <-ctx.Done():
				return
			case <-time.After(settleDelay):
			}
		}
		d.reconcile()
	}
}

// trimDaemonLog keeps launchd's stdout and stderr file, which only panics
// reach, from growing without bound: past 1 MiB it moves to .1 and starts
// again. launchd appends, so truncating in place is safe.
func trimDaemonLog(path string) {
	info, err := os.Stat(path)
	if err != nil || info.Size() <= 1<<20 {
		return
	}
	if data, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".1", data, 0o600)
	}
	_ = os.Truncate(path, 0)
}

// persist stores what the user asks for and then takes it as current;
// storing is the commit point, so a failed write changes nothing.
func (d *Daemon) persist(next State) error {
	if err := store.WriteJSON(d.opts.Layout.State(), next, 0o600); err != nil {
		return err
	}
	d.mu.Lock()
	d.state = next
	d.mu.Unlock()
	return nil
}

// saveSecrets is called with d.mu held.
func (d *Daemon) saveSecrets() error {
	return store.WriteJSON(d.opts.Layout.Secrets(), d.secrets, 0o600)
}

// revision is called with d.mu held.
func (d *Daemon) revision() string {
	if d.cfg == nil {
		return ""
	}
	return d.cfg.Root.Revision()
}

func (d *Daemon) setStatus(status, lastErr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status = status
	d.since = time.Now()
	d.lastErr = lastErr
}
