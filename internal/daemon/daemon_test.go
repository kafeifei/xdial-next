package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/kafeifei/xdial-next/internal/subscription"
	"github.com/kafeifei/xdial-next/internal/sysdns"
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
		case subscription.ParseCommand:
			os.Exit(subscription.RunParseChild(os.Stdin, os.Stdout, os.Stderr))
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
	// What doctor reads.
	upstream      error
	supplementals []sysdns.Supplemental
	vpns          []string
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

func (f *fakeSystem) Upstream(netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.upstream
}

func (f *fakeSystem) Supplementals() ([]sysdns.Supplemental, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.supplementals, nil
}

func (f *fakeSystem) VPNs() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vpns, nil
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
	h.fails("secret.set", map[string]any{"name": "big", "value": strings.Repeat("x", MaxSecretLength+1)}, cli.CodeSecretFormat)
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
	// A first connect that failed is reported as failed, not as never made.
	if c := b.doctorChecks()["connection"]; c["status"] != "fail" || c["detail"] == nil {
		t.Errorf("doctor after a failed first connect: %v", c)
	}
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
	// A download for something else while the rule set is still missing
	// leaves the stopped retries alone.
	h.d.resumeAfterFetch()
	if s := h.ok("status", nil); s["state"] != "failed" {
		t.Errorf("an unrelated download lifted the stopped retries: %v", s)
	}
	h.seedRuleSet("r", url, `{"version": 1, "rules": [{"domain": ["b.example"]}]}`)
	// A download that brings content in is what calls this.
	h.d.resumeAfterFetch()
	if s := h.ok("status", nil); s["state"] != "connected" {
		t.Errorf("a filled cache did not bring the connection back: %v", s)
	}
}

func TestRedownloadMarkSurvivesAFailedDownload(t *testing.T) {
	h := start(t, nil)
	const url = "https://rules.example.com/r.json"
	h.ok("config.apply", map[string]any{"content": remoteDoc(url)})
	path := filepath.Join(h.layout.Resources(), "rule-sets", "r."+fingerprint(url, "source")[:16]+".json")
	h.d.mu.Lock()
	h.d.invalid = map[string]bool{path: true}
	h.d.mu.Unlock()
	h.d.refreshResources() // the download fails on the test network
	if !h.d.markedInvalid(path) {
		t.Error("a failed download dropped the mark")
	}
	h.seedRuleSet("r", url, `{"version": 1, "rules": [{"domain": ["a.example"]}]}`)
	h.d.dropInvalid(path, func() bool { return true })
	if h.d.markedInvalid(path) {
		t.Error("a valid cache kept the mark")
	}
}

const subDoc = `{"version": 1,
	"lines": [{"id": "jp", "type": "trojan", "server": "127.0.0.1", "server_port": 9, "password": {"secret": "jp"}}],
	"groups": [{"id": "proxy", "type": "selector", "outbounds": [{"subscription": "air", "filter": "香港"}, "jp"]},
	           {"id": "only-sub", "type": "selector", "outbounds": [{"subscription": "air", "filter": "美国"}]}],
	"subscriptions": [{"id": "air", "url": {"secret": "air-url"}}],
	"scenarios": [{"id": "s", "rules": [{"subscription": "air", "policies": {"Proxy": "proxy", "DIRECT": "direct"}}], "final": "direct"},
	              {"id": "empty", "rules": [], "final": "only-sub"}]}`

// seedSubscription writes downloaded content for subscription id into the
// cache, as a download of url would have.
func (h *harness) seedSubscription(id, url, content string) {
	h.t.Helper()
	fp := fingerprint(url, "subscription\n"+defaultUserAgent)
	path := filepath.Join(h.layout.Resources(), "subscriptions", id+"."+fp[:16]+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		h.t.Fatal(err)
	}
	var c subscription.Content
	if err := json.Unmarshal([]byte(content), &c); err != nil {
		h.t.Fatal(err)
	}
	if err := store.WriteJSON(path, cachedSubscription{Fingerprint: fp, FetchedAt: time.Now(), ChangedAt: time.Now(), Content: c}, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

const airCache = `{"format": "clash",
	"nodes": [
		{"name": "香港 01", "outbound": {"type": "shadowsocks", "server": "127.0.0.1", "server_port": 9, "method": "aes-128-gcm", "password": "node-secret"}},
		{"name": "日本 01", "outbound": {"type": "trojan", "server": "127.0.0.1", "server_port": 9, "password": "node-secret"}}],
	"rules": [
		{"policy": "Proxy", "rule": {"domain_suffix": ["google.com"]}},
		{"policy": "DIRECT", "rule": {"domain": ["a.example"]}}],
	"unsupported": {"rule:geoip": 2}}`

func TestCachedSubscriptionConnects(t *testing.T) {
	h := start(t, nil)
	const url = "https://sub.example/token"
	h.ok("config.apply", map[string]any{"content": subDoc})
	h.ok("secret.set", map[string]any{"name": "jp", "value": "a-password"})
	h.ok("secret.set", map[string]any{"name": "air-url", "value": url})
	h.seedSubscription("air", url, airCache)
	if s := h.ok("connect", map[string]any{"scenario": "s"}); s["state"] != "connected" {
		t.Fatalf("connect with a cached subscription: %v", s)
	}
	list := h.ok("subscription.list", nil)["subscriptions"].([]any)[0].(map[string]any)
	if list["cached"] != true || list["nodes"] != float64(2) || list["rules"] != float64(2) ||
		fmt.Sprint(list["policies"]) != "[map[name:Proxy rules:1] map[name:DIRECT rules:1]]" || fmt.Sprint(list["unsupported"]) != "map[rule:geoip:2]" {
		t.Errorf("subscription list: %v", list)
	}
	show := h.call("subscription.show", map[string]any{"id": "air"})
	if !show.OK || strings.Contains(string(show.Result), "node-secret") || !strings.Contains(string(show.Result), "香港 01") {
		t.Errorf("subscription show: %s", show.Result)
	}
	// A group the filters leave empty refuses to connect, and says why.
	h.fails("scenario.use", map[string]any{"id": "empty"}, cli.CodeResourceMissing)
	if s := h.ok("status", nil); s["state"] != "connected" || s["scenario"] != "s" {
		t.Errorf("a refused switch changed the connection: %v", s)
	}
}

func TestSubscriptionCacheWithSecretReferenceIsNotConnectedFrom(t *testing.T) {
	h := start(t, nil)
	const url = "https://sub.example/token"
	h.ok("config.apply", map[string]any{"content": subDoc})
	h.ok("secret.set", map[string]any{"name": "jp", "value": "a-password"})
	h.ok("secret.set", map[string]any{"name": "air-url", "value": url})
	h.seedSubscription("air", url, strings.Replace(airCache, `"password": "node-secret"}}],`, `"password": {"secret": "jp"}}}],`, 1))
	// Compiling checks the cached content again: a node that references a
	// secret is never compiled, so the scenario's subscription is missing.
	h.fails("connect", map[string]any{"scenario": "s"}, cli.CodeResourceDownload)
}

func TestMissingSubscriptionIsDownloadedFirst(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": subDoc})
	h.ok("secret.set", map[string]any{"name": "jp", "value": "a-password"})
	h.fails("connect", map[string]any{"scenario": "s"}, cli.CodeSecretMissing)
	h.ok("secret.set", map[string]any{"name": "air-url", "value": "https://sub.example/token"})
	h.fails("connect", map[string]any{"scenario": "s"}, cli.CodeResourceDownload)
	h.fails("subscription.show", map[string]any{"id": "air"}, cli.CodeResourceMissing)
	h.fails("subscription.update", map[string]any{"ids": []string{"nope"}}, cli.CodeConfigConflict)
}

func TestEndpointStatusIsReported(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": `{"version": 1,
		"lines": [{"id": "corp", "type": "openconnect", "flavor": "anyconnect", "server": "https://127.0.0.1:9",
		           "username": "u", "password": {"secret": "corp"}}],
		"rule_sets": [{"id": "r", "type": "inline", "rules": [{"domain_suffix": ["corp.example"]}]}],
		"scenarios": [{"id": "s", "rules": [{"rule_set": "r", "line": "corp"}], "final": "direct"}]}`})
	h.ok("secret.set", map[string]any{"name": "corp", "value": "a-password"})
	// sing-box brings the endpoint up in the background: the connection
	// is up while the VPN is not, and status says so.
	if s := h.ok("connect", map[string]any{"scenario": "s"}); s["state"] != "connected" {
		t.Fatalf("connect: %v", s)
	}
	s := h.waitFor("the endpoint's state", func(s map[string]any) bool {
		e, _ := s["endpoints"].(map[string]any)
		corp, _ := e["corp"].(map[string]any)
		return corp != nil && corp["type"] == "openconnect" && (corp["state"] == "failed" || corp["state"] == "connecting")
	})
	corp := s["endpoints"].(map[string]any)["corp"].(map[string]any)
	if corp["state"] == "failed" && corp["error"] == "" {
		t.Errorf("a failed endpoint without a reason: %v", corp)
	}
	events, _ := os.ReadFile(h.layout.Events())
	if !strings.Contains(string(events), "endpoint_state") {
		t.Error("no event for the endpoint's state")
	}
}

func TestTailscaleLoginNeedsALineOfTheConnection(t *testing.T) {
	h := start(t, nil)
	h.connected()
	h.fails("tailscale.login", map[string]any{"line": "hk"}, cli.CodeConfigConflict)
	h.fails("tailscale.login", map[string]any{"line": "nope", "auth_key": "k"}, cli.CodeConfigConflict)
	h.fails("tailscale.login", map[string]any{"line": "nope", "auth_key": strings.Repeat("k", MaxSecretLength+1)}, cli.CodeSecretFormat)
	h.fails("tailscale.logout", map[string]any{"line": "hk"}, cli.CodeConfigConflict)
}

func TestReadLineSkipsOnlyTheOverlongLine(t *testing.T) {
	input := "short\n" + strings.Repeat("x", 300) + "\nnext\n"
	r := bufio.NewReaderSize(strings.NewReader(input), 16)
	var got []string
	for {
		line, err := readLine(r, 100)
		if err != nil {
			break
		}
		got = append(got, fmt.Sprintf("%q", line))
	}
	if strings.Join(got, ",") != `"short\n","","next\n"` {
		t.Errorf("lines: %v", got)
	}
}

func TestEndpointTextIsScrubbed(t *testing.T) {
	endpoints := map[string]engine.EndpointStatus{"corp": {Type: "openconnect", State: "auth_required",
		Error: "login failed for hunter2-secret", AuthMessage: "retry hunter2-secret", AuthURL: "https://login.example/a/1"}}
	scrubEndpoints(endpoints, newScrubber(map[string]Secret{"corp": {Value: "hunter2-secret"}}))
	e := endpoints["corp"]
	if strings.Contains(e.Error+e.AuthMessage, "hunter2") || e.AuthURL == "" {
		t.Errorf("scrubbed status: %+v", e)
	}
	// The cases review found: a secret the engine's 64 KiB cut split,
	// behind copies scrubbing shortens; a short secret inside a long one,
	// whose placeholder is longer than it; a short text that is all secret.
	cookie := strings.Repeat("c", 2048)
	corp := "PRIVATE_PREFIX_" + strings.Repeat("X", 1000) + strings.Repeat("abcd", 258) + "Z"
	for name, c := range map[string]struct {
		text    string
		secrets map[string]Secret
		leak    string
	}{
		"split cookie": {strings.ToValidUTF8(("login failed: " + strings.Repeat(cookie+" ", 32))[:64<<10], ""),
			map[string]Secret{"corp": {Value: cookie}}, "cccc"},
		"nested secret": {strings.ToValidUTF8(("login failed: " + strings.Repeat(corp+" ", 32))[:64<<10], ""),
			map[string]Secret{"corp": {Value: corp}, "pin": {Value: "abcd"}}, "PRIVATE"},
		"all secret": {"PRIVATE_PREFIX_" + strings.Repeat("abcd", 16) + "…[engine-cut]",
			map[string]Secret{"corp": {Value: "PRIVATE_PREFIX_" + strings.Repeat("abcd", 16) + "…[engine-cut]"}, "pin": {Value: "abcd"}}, "PRIVATE"},
	} {
		got := scrubText(c.text, newScrubber(c.secrets))
		if strings.Contains(got, c.leak) || len(got) > maxEndpointText+len("…") {
			t.Errorf("%s: %q", name, got)
		}
	}
	// A secret straddling the cut is scrubbed before it is cut.
	long := map[string]engine.EndpointStatus{"corp": {Error: strings.Repeat("x", maxEndpointText-5) + "hunter2-secret"}}
	scrubEndpoints(long, newScrubber(map[string]Secret{"corp": {Value: "hunter2-secret"}}))
	if strings.Contains(long["corp"].Error, "hunt") {
		t.Errorf("part of a secret survived the cut: %s", long["corp"].Error[maxEndpointText-10:])
	}
}

func TestLoginLinksStayOutOfTheLog(t *testing.T) {
	line := "INFO endpoint/tailscale[tailnet]: Waiting for authentication: https://login.tailscale.com/a/abc123"
	if got := withoutLoginLinks(line); strings.Contains(got, "abc123") || !strings.Contains(got, "Waiting for authentication") {
		t.Errorf("log line: %s", got)
	}
}

func TestWaitAnswersForItsConnectionOnly(t *testing.T) {
	h := start(t, nil)
	h.connected()
	h.d.mu.Lock()
	c := h.d.conn
	h.d.mu.Unlock()
	h.ok("disconnect", nil)
	if _, err := h.d.waitLine(c, "tailnet", func(engine.EndpointStatus) bool { return false }); !cli.Is(err, cli.CodeConfigConflict) {
		t.Errorf("waiting on a connection that is gone: %v", err)
	}
}

func TestLoginLinksGoBeforeScrubbing(t *testing.T) {
	// A stored secret "auth" would turn "authentication" into something
	// the login link pattern no longer finds.
	scrub := newScrubber(map[string]Secret{"old": {Value: "auth"}})
	line := "Waiting for authentication: https://login.tailscale.com/a/abc123"
	if got := scrub.scrub(withoutLoginLinks(line)); strings.Contains(got, "abc123") {
		t.Errorf("log line: %s", got)
	}
}

const groupDoc = `{"version": 1,
	"lines": [{"id": "a", "type": "trojan", "server": "127.0.0.1", "server_port": 9, "password": {"secret": "p"}},
	          {"id": "b", "type": "trojan", "server": "127.0.0.1", "server_port": 9, "password": {"secret": "p"}}],
	"groups": [{"id": "pick", "type": "selector", "outbounds": ["a", "b"]},
	           {"id": "fast", "type": "urltest", "outbounds": ["a", "b"]}],
	"scenarios": [{"id": "s", "rules": [], "final": "pick"}, {"id": "t", "rules": [], "final": "fast"}]}`

func TestGroupSelectSwitchesAndPersists(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": groupDoc})
	h.ok("secret.set", map[string]any{"name": "p", "value": "a-password"})
	pid := h.ok("connect", map[string]any{"scenario": "s"})["engine_pid"]
	h.waitFor("the group's status", func(s map[string]any) bool {
		g, _ := s["groups"].(map[string]any)
		return g != nil && g["pick"] != nil
	})
	r := h.ok("group.select", map[string]any{"group": "pick", "member": "b"})
	if r["applied"] != true {
		t.Errorf("select: %v", r)
	}
	s := h.ok("status", nil)
	if s["engine_pid"] != pid || s["groups"].(map[string]any)["pick"].(map[string]any)["now"] != "b" {
		t.Errorf("after select: pid %v -> %v, groups %v", pid, s["engine_pid"], s["groups"])
	}
	// A reload compiles the choice as the default.
	h.ok("scenario.use", map[string]any{"id": "t"})
	h.ok("scenario.use", map[string]any{"id": "s"})
	h.waitFor("the choice after a reload", func(s map[string]any) bool {
		g, _ := s["groups"].(map[string]any)
		pick, _ := g["pick"].(map[string]any)
		return pick != nil && pick["now"] == "b"
	})
	h.fails("group.select", map[string]any{"group": "fast", "member": "a"}, cli.CodeConfigConflict)
	h.fails("group.select", map[string]any{"group": "pick", "member": "nope"}, cli.CodeConfigConflict)
}

func TestSubscriptionMembersCanBeSelectedAndTested(t *testing.T) {
	h := start(t, nil)
	const url = "https://sub.example/token"
	h.ok("config.apply", map[string]any{"content": subDoc})
	h.ok("secret.set", map[string]any{"name": "jp", "value": "a-password"})
	h.ok("secret.set", map[string]any{"name": "air-url", "value": url})
	h.seedSubscription("air", url, airCache)
	h.ok("connect", map[string]any{"scenario": "s"})
	h.waitFor("the group's status", func(s map[string]any) bool {
		g, _ := s["groups"].(map[string]any)
		return g != nil && g["proxy"] != nil
	})
	const member = "xdial:sub:air:香港 01"
	h.ok("group.select", map[string]any{"group": "proxy", "member": "jp"})
	if r := h.ok("group.select", map[string]any{"group": "proxy", "member": member}); r["applied"] != true {
		t.Errorf("select a subscription member: %v", r)
	}
	if now := h.ok("status", nil)["groups"].(map[string]any)["proxy"].(map[string]any)["now"]; now != member {
		t.Errorf("now: %v", now)
	}
	results := h.ok("line.test", map[string]any{"ids": []string{"proxy"}})["results"].(map[string]any)
	if results[member] == nil || results["jp"] == nil {
		t.Errorf("test a subscription member: %v", results)
	}
}

func TestSelectionOfARemovedMemberIsDropped(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": groupDoc})
	h.ok("group.select", map[string]any{"group": "pick", "member": "b"})
	// b leaves the group and comes back: the group's default is in use
	// again, not the old choice.
	without := strings.Replace(groupDoc, `"outbounds": ["a", "b"]},
	           {"id": "fast"`, `"outbounds": ["a"]},
	           {"id": "fast"`, 1)
	if without == groupDoc {
		t.Fatal("the test document changed")
	}
	h.ok("config.apply", map[string]any{"content": without})
	if picked := h.d.selections(); len(picked) != 0 {
		t.Errorf("after b left: %v", picked)
	}
	h.ok("config.apply", map[string]any{"content": groupDoc})
	h.ok("secret.set", map[string]any{"name": "p", "value": "a-password"})
	h.ok("connect", map[string]any{"scenario": "s"})
	h.waitFor("the group's default", func(s map[string]any) bool {
		g, _ := s["groups"].(map[string]any)
		pick, _ := g["pick"].(map[string]any)
		return pick != nil && pick["now"] == "a"
	})
}

func TestSelectionsSurviveAnApplyThatFails(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": groupDoc})
	h.ok("secret.set", map[string]any{"name": "p", "value": "a-password"})
	h.ok("connect", map[string]any{"scenario": "s"})
	h.ok("group.select", map[string]any{"group": "pick", "member": "b"})
	// The new configuration comes up but cannot be stored: the old one
	// comes back, and with it the choice its group had.
	if err := os.Remove(h.layout.Config()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(h.layout.Config(), 0o700); err != nil {
		t.Fatal(err)
	}
	without := strings.Replace(groupDoc, `"outbounds": ["a", "b"]},
	           {"id": "fast"`, `"outbounds": ["a"]},
	           {"id": "fast"`, 1)
	if r := h.call("config.apply", map[string]any{"content": without}); r.OK {
		t.Fatal("apply succeeded without storing")
	}
	if picked := h.d.selections(); picked["pick"] != "b" {
		t.Errorf("after the failed apply: %v", picked)
	}
}

func TestSelectionOutsideAFilterIsDropped(t *testing.T) {
	h := start(t, nil)
	const url = "https://sub.example/token"
	h.ok("config.apply", map[string]any{"content": subDoc})
	h.ok("secret.set", map[string]any{"name": "air-url", "value": url})
	h.seedSubscription("air", url, airCache)
	h.ok("group.select", map[string]any{"group": "proxy", "member": "xdial:sub:air:香港 01"})
	excluded := strings.Replace(subDoc, `"filter": "香港"}`, `"filter": "香港", "exclude": "01"}`, 1)
	if excluded == subDoc {
		t.Fatal("the test document changed")
	}
	h.ok("config.apply", map[string]any{"content": excluded})
	if picked := h.d.selections(); len(picked) != 0 {
		t.Errorf("a node the filter leaves out: %v", picked)
	}
	// A group the filters leave empty has no members, not the direct put
	// in for sing-box.
	h.ok("config.apply", map[string]any{"content": strings.Replace(subDoc, `"filter": "香港"}, "jp"]`, `"filter": "香港"}, "jp", "direct"]`, 1)})
	h.ok("group.select", map[string]any{"group": "proxy", "member": "direct"})
	h.ok("config.apply", map[string]any{"content": strings.Replace(subDoc, `"filter": "香港"}, "jp"]`, `"filter": "美国"}]`, 1)})
	if picked := h.d.selections(); len(picked) != 0 {
		t.Errorf("direct in a group left empty: %v", picked)
	}
}

func TestSelectRightAfterConnectReachesTheEngine(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": groupDoc})
	h.ok("secret.set", map[string]any{"name": "p", "value": "a-password"})
	h.ok("connect", map[string]any{"scenario": "s"})
	// No status from the engine yet, perhaps: the choice still goes to it.
	h.ok("group.select", map[string]any{"group": "pick", "member": "b"})
	h.waitFor("the choice in use", func(s map[string]any) bool {
		g, _ := s["groups"].(map[string]any)
		pick, _ := g["pick"].(map[string]any)
		return pick != nil && pick["now"] == "b"
	})
}

func TestLineTestAnswersThroughTheEngine(t *testing.T) {
	h := start(t, nil)
	h.fails("line.test", map[string]any{"ids": []string{"a"}}, cli.CodeConfigConflict)
	h.ok("config.apply", map[string]any{"content": groupDoc})
	h.ok("secret.set", map[string]any{"name": "p", "value": "a-password"})
	h.ok("connect", map[string]any{"scenario": "s"})
	// Only what the engine runs; an unknown id is not echoed back at length.
	h.fails("line.test", map[string]any{"ids": []string{"pick", strings.Repeat("n", 1<<16)}}, cli.CodeConfigConflict)
	if r := h.ok("line.test", map[string]any{"ids": []string{"direct"}}); r["results"].(map[string]any)["direct"] == nil {
		t.Errorf("direct: %v", r)
	}
	r := h.ok("line.test", map[string]any{"ids": []string{"pick"}})
	results := r["results"].(map[string]any)
	// Nothing listens on port 9: each member answers with an error.
	for _, tag := range []string{"a", "b"} {
		o, _ := results[tag].(map[string]any)
		if o == nil || o["error"] == nil {
			t.Errorf("%s: %v", tag, results)
		}
	}
}

func TestScrubberMasksOverlaps(t *testing.T) {
	for name, c := range map[string]struct {
		secrets    map[string]Secret
		text, want string
	}{
		"two secrets overlap":      {map[string]Secret{"a": {Value: "abcd"}, "b": {Value: "cdefgh"}}, "x abcdefgh y", "x <secret:a> y"},
		"a secret overlaps itself": {map[string]Secret{"s": {Value: "ababa"}}, "x abababa y", "x <secret:s> y"},
		"json escapes":             {map[string]Secret{"s": {Value: "a<b>\x01cd"}}, `msg "a\u003cb\u003e\u0001cd"`, `msg "<secret:s>"`},
		"quoted":                   {map[string]Secret{"s": {Value: "a<b>\x01cd"}}, `msg "a<b>\x01cd"`, `msg "<secret:s>"`},
		"JSON.stringify":           {map[string]Secret{"s": {Value: "pass\u2028\"word\n"}}, "msg \"pass\u2028\\\"word\\n\"", `msg "<secret:s>"`},
		"quotes escaped only":      {map[string]Secret{"s": {Value: "a\"b\x01cd"}}, "msg \"a\\\"b\x01cd\"", `msg "<secret:s>"`},
	} {
		if got := newScrubber(c.secrets).scrub(c.text); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestScrubberRunsInBoundedSpace(t *testing.T) {
	// Many names for one value, and a value that overlaps itself, over
	// text that is nothing but that value: one span each time, found a
	// period at a time.
	secrets := map[string]Secret{}
	for i := range 100 {
		secrets[fmt.Sprintf("s%03d", i)] = Secret{Value: "aaaa"}
	}
	secrets["long"] = Secret{Value: strings.Repeat("a", MaxSecretLength)}
	s := newScrubber(secrets)
	if len(s.forms) > 20 {
		t.Errorf("%d forms for two values", len(s.forms))
	}
	text := strings.Repeat("a", 1<<20)
	if spans := s.spans(text); len(spans) != 1 || spans[0] != (span{0, len(text), "long"}) && spans[0] != (span{0, len(text), "s000"}) {
		t.Errorf("spans: %v", spans)
	}
	if got := s.scrub("x" + strings.Repeat("ab", 1000) + "aaaa y"); got != "x"+strings.Repeat("ab", 1000)+"<secret:long> y" && got != "x"+strings.Repeat("ab", 1000)+"<secret:s000> y" {
		t.Errorf("scrub: %q", got)
	}
}

func TestStoredLongSecretIsRefused(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": doc})
	h.d.mu.Lock()
	h.d.secrets["hk"] = Secret{Value: strings.Repeat("x", MaxSecretLength+1)}
	h.d.mu.Unlock()
	h.fails("connect", map[string]any{"scenario": "s"}, cli.CodeSecretFormat)
}

func TestEndpointTextStaysBounded(t *testing.T) {
	// The longest secret in its longest form, JSON escapes, starting early
	// in text the engine cut at 64 KiB: it ends before that cut.
	value := strings.Repeat("<", MaxSecretLength)
	form := strings.Repeat(`\u003c`, MaxSecretLength)
	text := ("err: " + form + " " + strings.Repeat("y", 64<<10))[:64<<10]
	if got := scrubText(text, newScrubber(map[string]Secret{"s": {Value: value}})); got != "err: …" {
		t.Errorf("long secret: %q", got)
	}
	// Masks longer than what they hide do not push it past the bound.
	name := strings.Repeat("n", 63)
	got := scrubText(strings.Repeat("abcd ", 100), newScrubber(map[string]Secret{name: {Value: "abcd"}}))
	if len(got) > maxEndpointText+len("…") || strings.Contains(got, "abcd") || !strings.HasSuffix(got, "…") {
		t.Errorf("masked text: %d bytes, %q", len(got), got)
	}
	if got := scrubText("short", newScrubber(nil)); got != "short" {
		t.Errorf("short text: %q", got)
	}
}

func TestSafeCutNeverSplitsASecret(t *testing.T) {
	s := newScrubber(map[string]Secret{"a": {Value: "secret-value"}, "b": {Value: "中文密码"}})
	text := strings.Repeat("x", 505) + "secret-value" + strings.Repeat("y", 100)
	if cut := s.safeCut(text, 512); cut != 505 {
		t.Errorf("cut at %d, want 505", cut)
	}
	text = strings.Repeat("x", 509) + "中文密码" + strings.Repeat("y", 100)
	if cut := s.safeCut(text, 512); cut != 509 {
		t.Errorf("cut at %d, want 509", cut)
	}
	text = strings.Repeat("x", 510) + "中" + strings.Repeat("y", 100)
	if cut := s.safeCut(text, 512); cut != 510 {
		t.Errorf("cut inside a character: %d", cut)
	}
	if cut := s.safeCut("short", 512); cut != 5 {
		t.Errorf("short text cut at %d", cut)
	}
}

// doctorChecks runs doctor and returns its checks by name.
func (h *harness) doctorChecks() map[string]map[string]any {
	checks := map[string]map[string]any{}
	for _, c := range h.ok("doctor", nil)["checks"].([]any) {
		m := c.(map[string]any)
		checks[m["name"].(string)] = m
	}
	return checks
}

func TestDoctor(t *testing.T) {
	h := start(t, nil)
	if c := h.doctorChecks()["connection"]; c["status"] != "fail" || c["hint"] == nil {
		t.Errorf("without a configuration: %v", c)
	}
	h.connected()
	checks := h.doctorChecks()
	for name, want := range map[string]string{"connection": "ok", "system_dns": "ok", "split_dns": "ok", "other_vpn": "ok",
		"physical_dns": "ok", "endpoints": "skip", "groups": "skip", "resources": "skip", "engine": "ok"} {
		if checks[name]["status"] != want {
			t.Errorf("connected, %s: %v, want %s", name, checks[name], want)
		}
	}
	if len(checks) != 9 {
		t.Errorf("%d checks", len(checks))
	}

	h.sys.mu.Lock()
	h.sys.supplementals = []sysdns.Supplemental{{Domain: "corp.example", Servers: []string{"10.0.0.53"}, Interface: "utun4"}}
	h.sys.vpns = []string{"Corp VPN"}
	h.sys.upstream = errors.New("i/o timeout")
	h.sys.mu.Unlock()
	h.d.events.add("engine_exited", map[string]any{"pid": 1})
	checks = h.doctorChecks()
	for name, want := range map[string]string{"split_dns": "warn", "other_vpn": "warn", "physical_dns": "fail", "engine": "warn"} {
		if checks[name]["status"] != want || checks[name]["detail"] == nil {
			t.Errorf("%s: %v, want %s", name, checks[name], want)
		}
	}
	h.d.events.add("retry_stopped", map[string]any{"failures": 5})
	if c := h.doctorChecks()["engine"]; c["status"] != "fail" {
		t.Errorf("reconnecting stopped: %v", c)
	}
}

func TestDoctorReportsDownloadFailures(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": remoteDoc("https://rules.example.com/r.json")})
	h.fails("rule_set.update", nil, cli.CodeResourceDownload)
	c := h.doctorChecks()["resources"]
	if c["status"] != "fail" || !strings.Contains(fmt.Sprint(c["detail"]), "规则集 r 下载失败，还没有缓存") {
		t.Errorf("resources: %v", c)
	}
}

func TestExplainPointsOutContentNewerThanTheEngine(t *testing.T) {
	h := start(t, nil)
	const url = "https://rules.example.com/r.json"
	h.ok("config.apply", map[string]any{"content": remoteDoc(url)})
	h.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	h.seedRuleSet("r", url, `{"version": 3, "rules": [{"domain_suffix": ["example.com"]}]}`)
	h.ok("connect", map[string]any{"scenario": "s"})
	e := h.ok("explain", map[string]any{"target": "www.example.com"})
	if e["rule"] == nil || strings.Contains(fmt.Sprint(e["notes"]), "不是同一份") {
		t.Errorf("before an update: %v", e)
	}
	// An update after the engine came up takes effect at the next connect:
	// explain answers by it, and says so.
	time.Sleep(10 * time.Millisecond)
	h.seedRuleSet("r", url, `{"version": 3, "rules": [{"domain_suffix": ["other.example"]}]}`)
	e = h.ok("explain", map[string]any{"target": "www.example.com"})
	if e["rule"] != nil || !strings.Contains(fmt.Sprint(e["notes"]), "规则集 r 和运行中的引擎用的不是同一份") {
		t.Errorf("after an update: %v", e)
	}
}

func TestRestartEndsRunAfterAnsweringAndKeepsTheIntent(t *testing.T) {
	h := start(t, nil)
	h.connected()
	h.d.opts.Restart = h.cancel
	if r := h.ok("daemon.restart", nil); r["restarting"] != true {
		t.Fatalf("restart: %v", r)
	}
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not end")
	}
	var state State
	if err := store.ReadJSON(h.layout.State(), &state); err != nil || !state.Connected {
		t.Errorf("intent after the restart: %+v %v", state, err)
	}
	h.done <- nil
}

func TestRestartIsRefusedWithoutAWayToRestart(t *testing.T) {
	h := start(t, nil)
	h.fails("daemon.restart", nil, cli.CodeConfigConflict)
}
