package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/kafeifei/xdial-next/internal/api"
	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
	"github.com/kafeifei/xdial-next/internal/paths"
	"github.com/kafeifei/xdial-next/internal/resource"
	"github.com/kafeifei/xdial-next/internal/store"
)

// The test binary doubles as the check child and the engine child.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case engine.CheckCommand:
			os.Exit(engine.RunCheckChild(os.Stdin, os.Stdout))
		case engine.EngineCommand:
			os.Exit(engine.RunEngineChild(os.Stdin, os.Stdout, os.Stderr, os.Args[2:]))
		case resource.FetchCommand:
			os.Exit(resource.RunFetchChild(os.Stdin, os.Stdout))
		case resource.DecodeCommand:
			os.Exit(resource.RunDecodeChild(os.Stdin, os.Stdout, os.Stderr))
		}
	}
	os.Exit(m.Run())
}

const doc = `{"version": 1,
	"lines": [{"id": "hk", "type": "trojan", "server": "127.0.0.1", "server_port": 9, "password": {"secret": "hk"}}],
	"rule_sets": [{"id": "r", "type": "inline", "rules": [{"domain_suffix": ["example.com"]}]}],
	"scenarios": [
		{"id": "s", "rules": [{"rule_set": "r", "line": "hk"}], "final": "direct"},
		{"id": "t", "rules": [], "final": "direct"}
	]}`

type dnsLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *dnsLog) add(s string) {
	l.mu.Lock()
	l.calls = append(l.calls, s)
	l.mu.Unlock()
}

func (l *dnsLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.calls, " ")
}

// fakeSystem stands in for scutil and the DNS probe.
type fakeSystem struct {
	log       *dnsLog
	mu        sync.Mutex
	physical  []netip.Addr
	hidden    bool // the key reads as missing once
	reads     int
	emptyFrom int // from this read on the physical DNS is gone; 0 never
	resolver  *fakeResolver
	onClose   func()
}

func (f *fakeSystem) PhysicalDNS() ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.emptyFrom > 0 && f.reads >= f.emptyFrom {
		return nil, nil
	}
	return f.physical, nil
}

func (f *fakeSystem) PhysicalInterface() (string, error) { return loopback(), nil }

func (f *fakeSystem) setPhysical(addr string) {
	f.mu.Lock()
	f.physical = []netip.Addr{netip.MustParseAddr(addr)}
	f.mu.Unlock()
}

func (f *fakeSystem) Hold(key string, lock *os.File) (Resolver, error) {
	f.log.add("hold")
	r := &fakeResolver{sys: f, changes: make(chan struct{}, 1), done: make(chan struct{})}
	f.mu.Lock()
	f.resolver = r
	f.mu.Unlock()
	return r, nil
}

func (f *fakeSystem) current() *fakeResolver {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resolver
}

func (f *fakeSystem) Resolver(string) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hidden {
		f.hidden = false
		return false, "192.0.2.1", nil
	}
	return true, "172.19.0.2", nil
}

func (f *fakeSystem) Probe() error      { return nil }
func (f *fakeSystem) FlushCache() error { f.log.add("flush"); return nil }

type fakeResolver struct {
	sys     *fakeSystem
	changes chan struct{}
	done    chan struct{}
	once    sync.Once
}

func (r *fakeResolver) Changes() <-chan struct{} { return r.changes }
func (r *fakeResolver) Done() <-chan struct{}    { return r.done }
func (r *fakeResolver) Republish() error         { r.sys.log.add("republish"); return nil }
func (r *fakeResolver) Close() {
	r.once.Do(func() {
		if r.sys.onClose != nil {
			r.sys.onClose()
		}
		r.sys.log.add("close")
		close(r.done)
	})
}

// notify is what a dynamic-store notification looks like to the daemon.
func (r *fakeResolver) notify() {
	select {
	case r.changes <- struct{}{}:
	default:
	}
}

type harness struct {
	t      *testing.T
	layout paths.Layout
	dns    *dnsLog
	sys    *fakeSystem
	client *api.Client
	cancel context.CancelFunc
	done   chan error
	d      *Daemon
}

func start(t *testing.T, authorize func(uint32) bool) *harness {
	t.Helper()
	// Unix socket paths are short on macOS; keep the root under /tmp.
	root, err := os.MkdirTemp("/tmp", "xd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	return startAt(t, root, "com.kafeifei.xdial.test", authorize)
}

func startAt(t *testing.T, root, id string, authorize func(uint32) bool) *harness {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if authorize == nil {
		authorize = func(uint32) bool { return true }
	}
	for _, dir := range []string{filepath.Join(root, "var", "run"), filepath.Join(root, "Library", "Application Support")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	log := &dnsLog{}
	sys := &fakeSystem{log: log, physical: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	h := &harness{t: t, layout: paths.Layout{ID: id, Root: root}, dns: log, sys: sys, done: make(chan error, 1)}
	d, err := New(Options{
		Layout: h.layout, Executable: exe, Authorize: authorize, NoTUN: true, System: sys,
		ExcludeFromBackup: func(string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.d = d
	go func() { h.done <- d.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.client, err = api.Dial(h.layout.Socket(), uint32(os.Getuid()))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon did not listen: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	if h.cancel == nil {
		return
	}
	h.client.Close()
	h.cancel()
	h.cancel = nil
	if err := <-h.done; err != nil {
		h.t.Errorf("daemon returned %v", err)
	}
}

func (h *harness) call(method string, params any) api.Response {
	h.t.Helper()
	var last api.Response
	if err := h.client.Call(method, params, func(r api.Response) bool { last = r; return true }); err != nil {
		h.t.Fatalf("%s: %v", method, err)
	}
	return last
}

func (h *harness) ok(method string, params any) map[string]any {
	h.t.Helper()
	r := h.call(method, params)
	if !r.OK {
		h.t.Fatalf("%s failed: %+v", method, r.Error)
	}
	var m map[string]any
	if err := json.Unmarshal(r.Result, &m); err != nil {
		h.t.Fatal(err)
	}
	return m
}

func (h *harness) fails(method string, params any, code string) {
	h.t.Helper()
	r := h.call(method, params)
	if r.OK || r.Error.Code != code {
		h.t.Fatalf("%s: want %s, got ok=%v %+v", method, code, r.OK, r.Error)
	}
}

func TestConnectDisconnect(t *testing.T) {
	h := start(t, nil)
	h.fails("connect", nil, cli.CodeConfigInvalid)

	dry := h.ok("config.apply", map[string]any{"content": doc, "dry_run": true})
	if dry["applied"] != false || len(dry["missing_secrets"].([]any)) != 1 {
		t.Fatalf("dry run: %v", dry)
	}
	applied := h.ok("config.apply", map[string]any{"content": doc})
	if applied["applied"] != true {
		t.Fatalf("apply: %v", applied)
	}
	revision := applied["revision"].(string)
	h.fails("config.apply", map[string]any{"content": doc, "if_match": "stale"}, cli.CodeConfigConflict)

	h.fails("connect", map[string]any{"scenario": "s"}, cli.CodeSecretMissing)
	h.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	status := h.ok("connect", map[string]any{"scenario": "s"})
	if status["state"] != "connected" || status["system_dns"] != true || status["engine_pid"].(float64) == 0 {
		t.Fatalf("connect: %v", status)
	}
	if got := h.dns.String(); got != "hold flush" {
		t.Errorf("dns calls %q", got)
	}
	if status["intent"] != "connected" || len(status["physical_dns"].([]any)) != 1 {
		t.Errorf("connect: %v", status)
	}
	// Connecting again to what is up changes nothing.
	if again := h.ok("connect", map[string]any{"scenario": "s"}); again["engine_pid"] != status["engine_pid"] {
		t.Errorf("a second connect restarted the engine: %v", again)
	}

	// Removing the scenario in use is refused while connected.
	h.fails("config.apply", map[string]any{"content": strings.Replace(doc, `"id": "s"`, `"id": "u"`, 1), "if_match": revision}, cli.CodeConfigConflict)
	h.fails("secret.rm", map[string]any{"name": "hk"}, cli.CodeSecretInUse)

	// Switching scenarios reloads.
	if s := h.ok("scenario.use", map[string]any{"id": "t"}); s["scenario"] != "t" || s["state"] != "connected" {
		t.Fatalf("scenario.use: %v", s)
	}

	// The intent is stored before anything is taken down, 6.3.
	h.sys.onClose = func() {
		state, _ := os.ReadFile(h.layout.State())
		if !strings.Contains(string(state), `"connected": false`) {
			t.Errorf("the resolver went before the intent was stored: %s", state)
		}
	}
	status = h.ok("disconnect", nil)
	if status["state"] != "disconnected" || status["system_dns"] != false || status["intent"] != "disconnected" {
		t.Fatalf("disconnect: %v", status)
	}
	if got := h.dns.String(); !strings.HasSuffix(got, "close") {
		t.Errorf("dns not cleared last: %q", got)
	}

	list := h.ok("secret.list", nil)
	secrets, _ := json.Marshal(list)
	if strings.Contains(string(secrets), "a-password") {
		t.Fatal("secret.list leaked a value")
	}
	var types []string
	if err := h.client.Call("logs", map[string]any{"lines": 50}, func(r api.Response) bool {
		var e Event
		if json.Unmarshal(r.Result, &e) == nil {
			types = append(types, e.Type)
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(types, " ")
	for _, want := range []string{"config_applied", "secret_set", "engine_started", "dns_set", "dns_cleared", "disconnected"} {
		if !strings.Contains(joined, want) {
			t.Errorf("event %s missing from %s", want, joined)
		}
	}
	events, _ := os.ReadFile(h.layout.Events())
	if strings.Contains(string(events), "a-password") {
		t.Fatal("the event log holds a secret value")
	}
}

func (h *harness) connected() int {
	h.t.Helper()
	h.ok("config.apply", map[string]any{"content": doc})
	h.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	return int(h.ok("connect", map[string]any{"scenario": "s"})["engine_pid"].(float64))
}

func (h *harness) waitFor(what string, ok func(map[string]any) bool) map[string]any {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s := h.ok("status", nil)
		if ok(s) {
			return s
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%s: %v", what, s)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestEngineCrashClearsDNSAndReconnects(t *testing.T) {
	h := start(t, nil)
	pid := h.connected()
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	h.waitFor("reconnect", func(s map[string]any) bool {
		return s["state"] == "connected" && int(s["engine_pid"].(float64)) != pid
	})
	// The resolver went before the restart: hold, close, hold.
	if got := h.dns.String(); got != "hold flush close hold flush" {
		t.Errorf("dns calls %q", got)
	}
}

func TestDisconnectDropsPendingRetry(t *testing.T) {
	h := start(t, nil)
	pid := h.connected()
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	h.waitFor("retry scheduled", func(s map[string]any) bool { return s["state"] == "connecting" })
	h.ok("disconnect", nil)
	time.Sleep(1500 * time.Millisecond)
	if s := h.ok("status", nil); s["state"] != "disconnected" || s["engine_pid"].(float64) != 0 {
		t.Fatalf("a retry outlived disconnect: %v", s)
	}
}

func TestPhysicalDNSChangeReloads(t *testing.T) {
	h := start(t, nil)
	pid := h.connected()
	h.sys.setPhysical("192.0.2.2")
	h.sys.current().notify()
	s := h.waitFor("reload", func(s map[string]any) bool {
		return s["state"] == "connected" && int(s["engine_pid"].(float64)) != pid
	})
	if dns := s["physical_dns"].([]any); len(dns) != 1 || dns[0] != "192.0.2.2" {
		t.Errorf("physical dns %v", dns)
	}
}

func TestLostKeyIsRepublished(t *testing.T) {
	h := start(t, nil)
	h.connected()
	h.sys.mu.Lock()
	h.sys.hidden = true
	h.sys.mu.Unlock()
	h.sys.current().notify()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(h.dns.String(), "republish") {
		if time.Now().After(deadline) {
			t.Fatalf("dns calls %q", h.dns.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDeadSessionIsReplaced(t *testing.T) {
	h := start(t, nil)
	pid := h.connected()
	h.sys.current().Close()
	deadline := time.Now().Add(5 * time.Second)
	for h.dns.String() != "hold flush close hold" {
		if time.Now().After(deadline) {
			t.Fatalf("dns calls %q", h.dns.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if s := h.ok("status", nil); s["state"] != "connected" || int(s["engine_pid"].(float64)) != pid {
		t.Errorf("replacing the session touched the engine: %v", s)
	}
}

func TestOneIdentityConnectedAtATime(t *testing.T) {
	a := start(t, nil)
	a.connected()
	b := startAt(t, a.layout.Root, "com.kafeifei.xdial.other", nil)
	b.ok("config.apply", map[string]any{"content": doc})
	b.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	b.fails("connect", map[string]any{"scenario": "s"}, cli.CodeEngineBusy)
	a.ok("disconnect", nil)
	b.ok("connect", map[string]any{"scenario": "s"})
}

func TestRestartResumes(t *testing.T) {
	h := start(t, nil)
	h.connected()
	h.stop()
	if got := h.dns.String(); !strings.HasSuffix(got, "close") {
		t.Errorf("stopping did not clear dns: %q", got)
	}
	state, _ := os.ReadFile(h.layout.State())
	if !strings.Contains(string(state), `"connected": true`) {
		t.Errorf("stopping changed the intent: %s", state)
	}
	again := startAt(t, h.layout.Root, h.layout.ID, nil)
	again.waitFor("resume", func(s map[string]any) bool { return s["state"] == "connected" })
}

func TestPeerCredentialsAreChecked(t *testing.T) {
	var seen uint32 = 1<<32 - 1
	h := start(t, func(uid uint32) bool { seen = uid; return false })
	r := h.call("status", nil)
	if r.OK || r.Error.Code != cli.CodeAPIPermission {
		t.Fatalf("unauthorized peer got %+v", r)
	}
	if seen != uint32(os.Getuid()) {
		t.Errorf("peer uid %d, want %d", seen, os.Getuid())
	}
}

func TestProtocolLimits(t *testing.T) {
	h := start(t, nil)
	conn, err := net.Dial("unix", h.layout.Socket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(`{"v": 9, "id": 1, "method": "status"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), cli.CodeAPIVersion) {
		t.Errorf("unknown version: %s", buf[:n])
	}
	if _, err := conn.Write([]byte(`{"v": 1, "id": 2, "method": "nope"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	n, _ = conn.Read(buf)
	if !strings.Contains(string(buf[:n]), cli.CodeUsage) {
		t.Errorf("unknown method: %s", buf[:n])
	}
}

func TestSocketPermissions(t *testing.T) {
	h := start(t, nil)
	for path, want := range map[string]os.FileMode{
		h.layout.SocketDir(): 0o755, h.layout.Socket(): 0o666, h.layout.Private(): 0o700, h.layout.Tailscale(): 0o700,
	} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %v", path, err, info.Mode().Perm(), want)
		}
	}
}

func TestClientChecksTheDaemon(t *testing.T) {
	h := start(t, nil)
	if _, err := api.Dial(h.layout.Socket(), uint32(os.Getuid())+1); !cli.Is(err, cli.CodeDaemonUntrusted) {
		t.Errorf("a daemon of another uid was trusted: %v", err)
	}
}

func TestConnectionLimit(t *testing.T) {
	h := start(t, nil)
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for range maxConnections - 1 {
		c, err := net.Dial("unix", h.layout.Socket())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	time.Sleep(100 * time.Millisecond)
	extra, err := api.Dial(h.layout.Socket(), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	var got api.Response
	if err := extra.Call("status", nil, func(r api.Response) bool { got = r; return true }); err != nil {
		t.Fatal(err)
	}
	if got.OK || got.Error.Code != cli.CodeDaemonBusy || got.ID != 1 {
		t.Errorf("over the limit: %+v", got)
	}
}

func TestScrubber(t *testing.T) {
	s := newScrubber(map[string]Secret{"hk": {Value: "p@ss word/1"}, "x": {Value: "ab"}})
	in := "a p@ss word/1 b " + "p%40ss+word%2F1" + " c cEBzcyB3b3JkLzE= ab"
	got := s.scrub(in)
	if strings.Contains(got, "p@ss") || strings.Contains(got, "p%40ss") || strings.Contains(got, "cEBzcyB3b3JkLzE") {
		t.Errorf("scrub left a form: %q", got)
	}
	if !strings.HasSuffix(got, " ab") {
		t.Errorf("short values must not be replaced: %q", got)
	}
}

// remoteDoc is doc with rule set r downloaded from url.
func remoteDoc(url string) string {
	return strings.Replace(doc, `{"id": "r", "type": "inline", "rules": [{"domain_suffix": ["example.com"]}]}`,
		`{"id": "r", "type": "remote", "format": "source", "url": "`+url+`"}`, 1)
}

func TestMissingRemoteRuleSetRefusesToConnect(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": remoteDoc("https://rules.example.com/r.json")})
	h.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	// Not in the cache, so connecting downloads it first; the test network
	// resolves nothing, and without the rule set there is no connection.
	h.fails("connect", map[string]any{"scenario": "s"}, cli.CodeResourceDownload)
	if s := h.ok("status", nil); s["state"] != "disconnected" || s["intent"] != "disconnected" {
		t.Errorf("a refused connect changed the state: %v", s)
	}
	// A scenario that does not use it still connects.
	h.ok("connect", map[string]any{"scenario": "t"})
}

func TestInvalidConnectKeepsPendingRetry(t *testing.T) {
	h := start(t, nil)
	pid := h.connected()
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	h.waitFor("retry scheduled", func(s map[string]any) bool { return s["state"] == "connecting" })
	h.fails("connect", map[string]any{"scenario": "nope"}, cli.CodeConfigConflict)
	h.waitFor("the retry still runs", func(s map[string]any) bool {
		return s["state"] == "connected" && s["scenario"] == "s"
	})
}

func TestDisconnectThatCannotBeStoredChangesNothing(t *testing.T) {
	h := start(t, nil)
	pid := h.connected()
	data := filepath.Dir(h.layout.State())
	if err := os.Chmod(data, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(data, 0o755) }()
	h.fails("disconnect", nil, cli.CodeInternal)
	if s := h.ok("status", nil); s["state"] != "connected" || int(s["engine_pid"].(float64)) != pid || s["intent"] != "connected" {
		t.Errorf("a failed disconnect changed the connection: %v", s)
	}
}

func TestApplyThatCannotBeStoredRestoresTheOldConfiguration(t *testing.T) {
	h := start(t, nil)
	h.connected()
	before := h.ok("config.export", nil)["revision"]
	data := filepath.Dir(h.layout.Config())
	if err := os.Chmod(data, 0o500); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(doc, `"final": "direct"},`, `"final": "hk"},`, 1)
	r := h.call("config.apply", map[string]any{"content": changed})
	_ = os.Chmod(data, 0o755)
	if r.OK {
		t.Fatal("apply succeeded without storing")
	}
	s := h.waitFor("old configuration back up", func(s map[string]any) bool { return s["state"] == "connected" })
	if s["revision"] != before || h.ok("config.export", nil)["revision"] != before {
		t.Errorf("revision moved: %v", s)
	}
}

func TestUnauthorizedCallersCannotTakeTheSlots(t *testing.T) {
	var open atomic.Bool
	h := start(t, func(uint32) bool { return open.Load() })
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for range maxConnections + maxRefusals + 8 {
		c, err := net.Dial("unix", h.layout.Socket())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	time.Sleep(100 * time.Millisecond)
	open.Store(true)
	c, err := api.Dial(h.layout.Socket(), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var got api.Response
	if err := c.Call("status", nil, func(r api.Response) bool { got = r; return true }); err != nil || !got.OK {
		t.Fatalf("an authorized caller was crowded out: %v %+v", err, got)
	}
}

func TestConnectionLockDirectoryMustBeOwnAndPrivate(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	l, err := acquireConnectionLock(shared, filepath.Join(shared, "connection.lock"))
	if err != nil {
		t.Fatal(err)
	}
	l.release()
	info, _ := os.Stat(shared)
	lock, _ := os.Stat(filepath.Join(shared, "connection.lock"))
	if info.Mode().Perm() != 0o700 || lock.Mode().Perm() != 0o600 {
		t.Errorf("modes %v %v", info.Mode(), lock.Mode())
	}
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireConnectionLock(shared, filepath.Join(shared, "connection.lock")); err == nil {
		t.Error("a directory others can enter was accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(shared, link); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireConnectionLock(link, filepath.Join(link, "connection.lock")); err == nil {
		t.Error("a symlinked directory was accepted")
	}
}

func TestFailedRollbackLeavesNothingUncommitted(t *testing.T) {
	h := start(t, nil)
	h.connected()
	before := h.ok("config.export", nil)["revision"]
	data := filepath.Dir(h.layout.Config())
	if err := os.Chmod(data, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(data, 0o755) }()
	// The new configuration comes up, cannot be stored, and the old one
	// cannot be prepared again because the physical DNS just went.
	h.sys.mu.Lock()
	h.sys.emptyFrom = h.sys.reads + 2
	h.sys.mu.Unlock()
	changed := strings.Replace(doc, `"final": "direct"},`, `"final": "hk"},`, 1)
	if r := h.call("config.apply", map[string]any{"content": changed}); r.OK {
		t.Fatal("apply succeeded without storing")
	}
	s := h.ok("status", nil)
	if s["engine_pid"].(float64) != 0 || s["revision"] != before {
		t.Fatalf("the uncommitted configuration kept running: %v", s)
	}
	h.sys.mu.Lock()
	h.sys.emptyFrom = 0
	h.sys.mu.Unlock()
	h.waitFor("the stored configuration back", func(s map[string]any) bool {
		return s["state"] == "connected" && s["revision"] == before
	})
}

func TestFollowSendsEachEventOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	l := newEventLog(path)
	l.add("before", nil)
	ch, past := l.follow(10)
	defer l.unsubscribe(ch)
	l.add("after", nil)
	if len(past) != 1 || past[0].Type != "before" {
		t.Fatalf("snapshot %v", past)
	}
	if e := <-ch; e.Type != "after" {
		t.Fatalf("followed %v", e)
	}
	select {
	case e := <-ch:
		t.Fatalf("an event came twice: %v", e)
	default:
	}
	// A restarted daemon reads the latest events back from the file.
	if again := newEventLog(path).recent(10); len(again) != 2 || again[1].Type != "after" {
		t.Errorf("after restart %v", again)
	}
}

// loopback is the name of the loopback interface, which tests bind to.
func loopback() string {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	return "lo"
}

// seedRuleSet writes a downloaded rule set into the cache, as a download of
// url would have.
func (h *harness) seedRuleSet(id, url, source string) {
	h.t.Helper()
	fp := fingerprint(url, "source")
	path := filepath.Join(h.layout.Resources(), "rule-sets", id+"."+fp[:16]+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		h.t.Fatal(err)
	}
	rules, _ := config.CheckRuleSetSource([]byte(source))
	entry := cachedRuleSet{Fingerprint: fp, Rules: len(rules), FetchedAt: time.Now(), ChangedAt: time.Now(), Source: json.RawMessage(source)}
	if err := store.WriteJSON(path, entry, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func TestCachedRuleSetConnects(t *testing.T) {
	h := start(t, nil)
	const url = "https://rules.example.com/r.json"
	h.ok("config.apply", map[string]any{"content": remoteDoc(url)})
	h.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	h.seedRuleSet("r", url, `{"version": 3, "rules": [{"domain_suffix": ["example.com"]}, {"ip_cidr": ["192.0.2.0/24"]}]}`)
	if s := h.ok("connect", map[string]any{"scenario": "s"}); s["state"] != "connected" {
		t.Fatalf("connect with a cached rule set: %v", s)
	}
	list := h.ok("rule_set.list", nil)["rule_sets"].([]any)
	r := list[0].(map[string]any)
	if r["id"] != "r" || r["cached"] != true || r["rules"] != float64(2) || r["next_update"] == nil {
		t.Errorf("rule-set list: %v", r)
	}
}

func TestCacheOfAnotherURLDoesNotCount(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": remoteDoc("https://rules.example.com/new.json")})
	h.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	h.seedRuleSet("r", "https://rules.example.com/old.json", `{"version": 1, "rules": [{"domain": ["a.example"]}]}`)
	h.fails("connect", map[string]any{"scenario": "s"}, cli.CodeResourceDownload)
	if r := h.ok("rule_set.list", nil)["rule_sets"].([]any)[0].(map[string]any); r["cached"] != false {
		t.Errorf("a cache of the old url counted: %v", r)
	}
}

func TestCorruptCacheIsNotConnectedFrom(t *testing.T) {
	h := start(t, nil)
	const url = "https://rules.example.com/r.json"
	h.ok("config.apply", map[string]any{"content": remoteDoc(url)})
	h.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	h.seedRuleSet("r", url, `{"version": 1, "rules": [{"process_name": ["x"], "query_type": ["A"]}]}`)
	// Connecting checks the cached content: content that fails is not
	// used but downloaded again, which the test network refuses.
	h.fails("connect", map[string]any{"scenario": "s"}, cli.CodeResourceDownload)
}

func TestRuleSetUpdateRefusesLoopback(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": remoteDoc("https://127.0.0.1:9/token-in-path")})
	resp := h.call("rule_set.update", map[string]any{"ids": []string{"r"}})
	if resp.OK || resp.Error.Code != cli.CodeResourceBlocked {
		t.Fatalf("want resource.blocked, got %+v", resp)
	}
	if strings.Contains(resp.Error.Message, "token-in-path") {
		t.Errorf("the url leaked into the error: %s", resp.Error.Message)
	}
	r := h.ok("rule_set.list", nil)["rule_sets"].([]any)[0].(map[string]any)
	if e, _ := r["last_error"].(map[string]any); e == nil || e["code"] != cli.CodeResourceBlocked {
		t.Errorf("list does not show the failure: %v", r)
	}
	if events, _ := os.ReadFile(h.layout.Events()); !strings.Contains(string(events), "rule_set_update_failed") {
		t.Error("no event for the failed download")
	}
}

func TestRuleSetUpdateNeedsARemoteRuleSet(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": doc})
	h.fails("rule_set.update", map[string]any{"ids": []string{"nope"}}, cli.CodeConfigConflict)
	h.fails("rule_set.update", map[string]any{"ids": []string{"r"}}, cli.CodeConfigConflict)
	if u := h.ok("rule_set.update", nil)["updated"].([]any); len(u) != 0 {
		t.Errorf("nothing to update, got %v", u)
	}
}

func TestCacheKeepsCharactersJSONWouldEscape(t *testing.T) {
	h := start(t, nil)
	d := &Daemon{opts: Options{Layout: h.layout}}
	source := []byte(`{"version":1,"rules":[{"process_name":["a&b<c>"]}]}`)
	entry := &cachedRuleSet{Fingerprint: fingerprint("https://x.example/r", "source"), Source: source}
	if err := d.writeRuleSet("r", entry); err != nil {
		t.Fatal(err)
	}
	var back cachedRuleSet
	if err := store.ReadJSON(d.ruleSetPath("r", entry.Fingerprint), &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Source, source) {
		t.Errorf("stored source changed: %s", back.Source)
	}
}

func TestConnectionResumesWhenTheCacheIsFilled(t *testing.T) {
	h := start(t, nil)
	const url = "https://rules.example.com/r.json"
	h.ok("config.apply", map[string]any{"content": remoteDoc(url)})
	h.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	// The user wants a connection that is down: retries found the rule set
	// missing from the cache and stopped.
	h.d.mu.Lock()
	h.d.state = State{Connected: true, Scenario: "s"}
	h.d.status = "failed"
	h.d.mu.Unlock()
	// Retries that stopped for another reason are left alone.
	h.d.resumeAfterFetch()
	if s := h.ok("status", nil); s["state"] != "failed" {
		t.Errorf("a download lifted retries that stopped for another reason: %v", s)
	}
	h.d.mu.Lock()
	h.d.awaitingCache = true
	h.d.mu.Unlock()
	h.seedRuleSet("r", url, `{"version": 1, "rules": [{"domain": ["b.example"]}]}`)
	// A download that brings content in is what calls this.
	h.d.resumeAfterFetch()
	if s := h.ok("status", nil); s["state"] != "connected" {
		t.Errorf("a filled cache did not bring the connection back: %v", s)
	}
}
