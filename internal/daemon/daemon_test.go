package daemon

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kafeifei/xdial-next/internal/api"
	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/engine"
	"github.com/kafeifei/xdial-next/internal/paths"
)

// The test binary doubles as the check child and the engine child.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case engine.CheckCommand:
			os.Exit(engine.RunCheckChild(os.Stdin, os.Stdout))
		case engine.EngineCommand:
			os.Exit(engine.RunEngineChild(os.Stdin, os.Stdout, os.Stderr, os.Args[2:]))
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

type harness struct {
	t      *testing.T
	layout paths.Layout
	dns    *dnsLog
	client *api.Client
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, authorize func(uint32, []uint32) bool) *harness {
	t.Helper()
	// Unix socket paths are short on macOS; keep the root under /tmp.
	root, err := os.MkdirTemp("/tmp", "xd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if authorize == nil {
		authorize = func(uint32, []uint32) bool { return true }
	}
	h := &harness{t: t, layout: paths.Layout{ID: "com.kafeifei.xdial.test", Root: root}, dns: &dnsLog{}, done: make(chan error, 1)}
	d, err := New(Options{
		Layout: h.layout, Executable: exe, Authorize: authorize, NoTUN: true,
		SetDNS:            func(key string, server netip.Addr) error { h.dns.add("set:" + server.String()); return nil },
		ClearDNS:          func(key string) error { h.dns.add("clear"); return nil },
		ExcludeFromBackup: func(string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- d.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.client, err = api.Dial(h.layout.Socket())
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
	if got := h.dns.String(); !strings.HasSuffix(got, "set:172.19.0.2") {
		t.Errorf("dns calls %q", got)
	}

	// Removing the scenario in use is refused while connected.
	h.fails("config.apply", map[string]any{"content": strings.Replace(doc, `"id": "s"`, `"id": "u"`, 1), "if_match": revision}, cli.CodeConfigConflict)
	h.fails("secret.rm", map[string]any{"name": "hk"}, cli.CodeSecretInUse)

	// Switching scenarios reloads.
	if s := h.ok("scenario.use", map[string]any{"id": "t"}); s["scenario"] != "t" || s["state"] != "connected" {
		t.Fatalf("scenario.use: %v", s)
	}

	status = h.ok("disconnect", nil)
	if status["state"] != "disconnected" || status["system_dns"] != false {
		t.Fatalf("disconnect: %v", status)
	}
	if got := h.dns.String(); !strings.HasSuffix(got, "clear") {
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

func TestEngineCrashClearsDNSAndReconnects(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": doc})
	h.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	pid := int(h.ok("connect", map[string]any{"scenario": "s"})["engine_pid"].(float64))
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		s := h.ok("status", nil)
		if s["state"] == "connected" && int(s["engine_pid"].(float64)) != pid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no reconnect: %v", s)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The resolver went before the restart: set, clear, set.
	if got := h.dns.String(); !strings.Contains(got, "set:172.19.0.2 clear set:172.19.0.2") {
		t.Errorf("dns calls %q", got)
	}
}

func TestRestartResumesAndClearsStaleDNS(t *testing.T) {
	h := start(t, nil)
	h.ok("config.apply", map[string]any{"content": doc})
	h.ok("secret.set", map[string]any{"name": "hk", "value": "a-password"})
	h.ok("connect", map[string]any{"scenario": "s"})
	h.stop()
	if got := h.dns.String(); !strings.HasSuffix(got, "clear") {
		t.Errorf("stopping did not clear dns: %q", got)
	}
	state, _ := os.ReadFile(h.layout.State())
	if !strings.Contains(string(state), `"connected": true`) {
		t.Errorf("stopping changed the desired state: %s", state)
	}
}

func TestPeerCredentialsAreChecked(t *testing.T) {
	var seen uint32 = 1<<32 - 1
	h := start(t, func(uid uint32, _ []uint32) bool { seen = uid; return false })
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
	info, err := os.Stat(h.layout.SocketDir())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("socket directory mode %v", info.Mode().Perm())
	}
	info, err = os.Stat(h.layout.Socket())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %v", info.Mode().Perm())
	}
	for _, path := range []string{h.layout.Private(), h.layout.Tailscale()} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", path, err, info.Mode().Perm())
		}
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
