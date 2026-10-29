package resource

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
)

func TestAllowed(t *testing.T) {
	for addr, want := range map[string]bool{
		"1.1.1.1":          true,
		"2606:4700::1111":  true,
		"127.0.0.1":        false,
		"::1":              false,
		"10.1.2.3":         false,
		"172.16.0.1":       false,
		"192.168.1.1":      false,
		"100.64.0.1":       false,
		"100.100.100.100":  false,
		"169.254.169.254":  false,
		"0.0.0.0":          false,
		"0.1.2.3":          false,
		"224.0.0.1":        false,
		"255.255.255.255":  false,
		"198.18.0.1":       false,
		"240.0.0.1":        false,
		"fc00::1":          false,
		"fe80::1":          false,
		"ff02::1":          false,
		"::ffff:127.0.0.1": false,
		"::ffff:8.8.8.8":   true,
		"64:ff9b::a00:1":   false,
		"64:ff9b::808:808": true,
		"2002:c0a8:101::1": false,
		"2002:808:808::1":  true,
		"2001:0:4136::1":   false,
		"2001:db8::1":      false,
		"fec0::1":          false,
	} {
		if got := Allowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Allowed(%s) = %v, want %v", addr, got, want)
		}
	}
}

func loopbackName(t *testing.T) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

// serve starts a TLS server and lets direct downloads reach it on
// loopback with its certificate trusted, for the duration of the test.
func serve(t *testing.T, h http.Handler) *httptest.Server {
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	prevAllowed, prevRoots := allowed, testRoots
	allowed, testRoots = func(netip.Addr) bool { return true }, pool
	t.Cleanup(func() { allowed, testRoots = prevAllowed, prevRoots })
	return srv
}

func get(t *testing.T, req FetchRequest) ([]byte, FetchResult) {
	t.Helper()
	if req.MaxBytes == 0 {
		req.MaxBytes = 1 << 10
	}
	if req.Interface == "" {
		req.Interface = loopbackName(t)
	}
	req.DNS = "127.0.0.1"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return fetch(ctx, req)
}

func TestFetch(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"v1"`)
			_, _ = w.Write([]byte("content"))
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
		case "/to-http":
			http.Redirect(w, r, "http://example.com/x", http.StatusFound)
		case "/to-ok":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/bad-location":
			w.Header().Set("Location", "https://example.com/token-in-location/%zz")
			w.WriteHeader(http.StatusFound)
		default:
			http.Error(w, "remote error page with secrets", http.StatusNotFound)
		}
	}))

	body, res := get(t, FetchRequest{URL: srv.URL + "/ok"})
	if res.Code != "" || string(body) != "content" || res.ETag != `"v1"` {
		t.Fatalf("ok: %q %+v", body, res)
	}
	if body, res = get(t, FetchRequest{URL: srv.URL + "/ok", ETag: `"v1"`}); res.Code != "" || !res.NotModified || body != nil {
		t.Errorf("not modified: %q %+v", body, res)
	}
	if body, res = get(t, FetchRequest{URL: srv.URL + "/to-ok"}); res.Code != "" || string(body) != "content" {
		t.Errorf("https redirect: %q %+v", body, res)
	}
	for path, code := range map[string]string{
		"/big":          cli.CodeResourceTooLarge,
		"/to-http":      cli.CodeResourceBlocked,
		"/loop":         cli.CodeResourceDownload,
		"/missing":      cli.CodeResourceDownload,
		"/bad-location": cli.CodeResourceDownload,
	} {
		if _, res := get(t, FetchRequest{URL: srv.URL + path}); res.Code != code {
			t.Errorf("%s: want %s, got %+v", path, code, res)
		} else if strings.Contains(res.Message, "secrets") || strings.Contains(res.Message, path) || strings.Contains(res.Message, "token") || strings.Contains(res.Message, "127.0.0.1") {
			t.Errorf("%s: the message echoes remote content or the url: %s", path, res.Message)
		}
	}
	if _, res := get(t, FetchRequest{URL: strings.Replace(srv.URL, "https", "http", 1) + "/ok"}); res.Code != cli.CodeResourceBlocked {
		t.Errorf("http: want blocked, got %+v", res)
	}
}

func TestFetchRefusesLoopbackForReal(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a direct download reached loopback")
	}))
	defer srv.Close()
	_, res := get(t, FetchRequest{URL: srv.URL + "/token-in-path?key=secret"})
	if res.Code != cli.CodeResourceBlocked {
		t.Fatalf("want blocked, got %+v", res)
	}
	if strings.Contains(res.Message, "token-in-path") || strings.Contains(res.Message, "secret") {
		t.Errorf("the url leaked: %s", res.Message)
	}
}

func TestFetchChecksEveryRedirect(t *testing.T) {
	// Two servers, so the redirect needs a new connection: the first dial
	// is let through, the one the redirect needs must be checked again.
	target := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the redirect reached a refused address")
	}))
	start := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/next", http.StatusFound)
	}))
	testRoots.AddCert(target.Certificate())
	dials := 0
	allowed = func(netip.Addr) bool {
		dials++
		return dials == 1
	}
	_, res := get(t, FetchRequest{URL: start.URL + "/start"})
	if res.Code != cli.CodeResourceBlocked || dials != 2 {
		t.Errorf("want the redirect refused on its own dial, got %+v after %d checks", res, dials)
	}
}
