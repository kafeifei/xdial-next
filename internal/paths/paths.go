// Package paths names every file and directory a daemon identity owns,
// ARCHITECTURE.md 6.1. Release and Debug builds are separate identities
// with separate paths, so both can be installed side by side; only the
// connection lock is shared, so only one of them is connected at a time.
package paths

import "path/filepath"

// Identities, ARCHITECTURE.md 6.1.
const (
	Release = "com.kafeifei.xdial"
	Debug   = "com.kafeifei.xdial.debug"
)

// Layout is the set of paths of one identity. Root prefixes every path and
// is empty outside tests.
type Layout struct {
	ID   string
	Root string
}

func (l Layout) at(parts ...string) string {
	root := l.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

// Data is the daemon's data directory.
func (l Layout) Data() string { return l.at("Library", "Application Support", l.ID) }

// Bin holds the copy of xdial the daemon runs, writable only by root.
func (l Layout) Bin() string { return filepath.Join(l.Data(), "bin", "xdial") }

// Config is the stored configuration, 4.1.
func (l Layout) Config() string { return filepath.Join(l.Data(), "config.json") }

// State is the runtime state, 4.1.
func (l Layout) State() string { return filepath.Join(l.Data(), "state.json") }

// Private is the root-only directory excluded from backups, 4.4.
func (l Layout) Private() string { return filepath.Join(l.Data(), "private") }

// Secrets is the credential store, 4.4.
func (l Layout) Secrets() string { return filepath.Join(l.Private(), "secrets.json") }

// Events is the event log, 6.5.
func (l Layout) Events() string { return filepath.Join(l.Private(), "events.jsonl") }

// EngineLog holds the engine's scrubbed log.
func (l Layout) EngineLog() string { return filepath.Join(l.Private(), "engine.log") }

// DaemonLog receives launchd's stdout and stderr for the daemon.
func (l Layout) DaemonLog() string { return filepath.Join(l.Private(), "daemon.log") }

// Resources holds downloaded rule sets and subscriptions, ARCHITECTURE.md
// 3.4. It is private: subscriptions carry the credentials of their nodes.
func (l Layout) Resources() string { return filepath.Join(l.Private(), "resources") }

// Tailscale holds tailscale state, one directory per line.
func (l Layout) Tailscale() string { return filepath.Join(l.Private(), "tailscale") }

// Plist is the launchd job.
func (l Layout) Plist() string { return l.at("Library", "LaunchDaemons", l.ID+".plist") }

// SocketDir holds the local API socket, 6.2.
func (l Layout) SocketDir() string { return l.at("var", "run", l.ID) }

// Socket is the local API socket.
func (l Layout) Socket() string { return filepath.Join(l.SocketDir(), "api.sock") }

// DNSKey is the dynamic-store key of the system resolver, 6.4.
func (l Layout) DNSKey() string { return "State:/Network/Service/" + l.ID + "/DNS" }

// SharedDir is the one directory every identity shares, root's alone: it
// holds the connection lock, 6.1. It is not under /var/run, which the
// daemon group can write, so no one but root can move it away.
func (l Layout) SharedDir() string { return l.at("Library", "Application Support", Release+".shared") }

// ConnectionLock is held by a daemon, with its engine and resolver
// session, for as long as it is connected; only one identity is connected
// at a time, 6.1.
func (l Layout) ConnectionLock() string { return filepath.Join(l.SharedDir(), "connection.lock") }
