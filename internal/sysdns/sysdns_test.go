package sysdns

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseServers(t *testing.T) {
	out := `<dictionary> {
  SearchDomains : <array> {
    0 : lan
  }
  ServerAddresses : <array> {
    0 : 192.168.64.1
    1 : fe80::1%en0
    2 : 2001:db8::53
  }
}
`
	got := parseServers(out)
	want := []string{"192.168.64.1", "fe80::1%en0", "2001:db8::53"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("%d: %s, want %s", i, got[i], want[i])
		}
	}
	if len(parseServers("  No such key\n")) != 0 {
		t.Error("an absent key has servers")
	}
}

func TestParseFirstResolver(t *testing.T) {
	out := `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 172.19.0.2
  flags    : Request A records

resolver #2
  nameserver[0] : 192.168.64.1
`
	if got, err := parseFirstResolver(out); err != nil || got != "172.19.0.2" {
		t.Errorf("got %q %v", got, err)
	}
	if _, err := parseFirstResolver("DNS configuration\n\nresolver #1\n  domain : local\n\nresolver #2\n"); err == nil {
		t.Error("resolver #1 without a nameserver passed")
	}
}

func TestKeyIsChecked(t *testing.T) {
	if _, err := Hold("State:/Network/Service/x y/DNS", netip.MustParseAddr(Server)); err == nil {
		t.Error("a key with a space was accepted")
	}
	if err := Clear("State:/Network/Global/DNS\nremove x"); err == nil {
		t.Error("a key with a newline was accepted")
	}
}

// serveDNS answers every query with rcode over UDP and TCP on one port.
func serveDNS(t *testing.T, rcode byte) netip.AddrPort {
	t.Helper()
	answer := func(q []byte) []byte {
		r := append([]byte(nil), q...)
		r[2] |= 0x80
		r[3] = r[3]&0xf0 | rcode
		return r
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(answer(buf[:n]), from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var size [2]byte
			if _, err := io.ReadFull(c, size[:]); err == nil {
				q := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(c, q); err == nil {
					r := answer(q)
					_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
				}
			}
			c.Close()
		}
	}()
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
}

func TestProbe(t *testing.T) {
	for _, tc := range []struct {
		rcode byte
		ok    bool
	}{{3, true}, {0, false}, {2, false}} {
		server := serveDNS(t, tc.rcode)
		err := probeAt(server, time.Second)
		if (err == nil) != tc.ok {
			t.Errorf("rcode %d: %v", tc.rcode, err)
		}
	}
	if err := probeAt(netip.MustParseAddrPort("127.0.0.1:1"), 200*time.Millisecond); err == nil {
		t.Error("nothing listening passed")
	}
}

func TestBuildQuery(t *testing.T) {
	q := buildQuery(0x1234, ProbeName)
	if binary.BigEndian.Uint16(q) != 0x1234 || !strings.Contains(string(q), "\x04_dns\x08resolver\x04arpa\x00") {
		t.Errorf("query % x", q)
	}
}

func TestPhysicalPrefersManualServers(t *testing.T) {
	stores := map[string]string{
		"show State:/Network/Global/IPv4\n":               "<dictionary> {\n  PrimaryInterface : en0\n  PrimaryService : F05D4BF0-6219\n  Router : 192.168.64.1\n}\n",
		"show Setup:/Network/Service/F05D4BF0-6219/DNS\n": "  No such key\n",
		"show State:/Network/Service/F05D4BF0-6219/DNS\n": "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 192.168.64.1\n  }\n}\n",
		"show State:/Network/Global/IPv6\n":               "  No such key\n",
	}
	defer func(r func(string, ...string) (string, error)) { Runner = r }(Runner)
	Runner = func(script string, _ ...string) (string, error) { return stores[script], nil }
	if got, err := Physical(); err != nil || len(got) != 1 || got[0].String() != "192.168.64.1" {
		t.Errorf("dhcp: %v %v", got, err)
	}
	stores["show Setup:/Network/Service/F05D4BF0-6219/DNS\n"] = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 223.5.5.5\n  }\n}\n"
	if got, err := Physical(); err != nil || len(got) != 1 || got[0].String() != "223.5.5.5" {
		t.Errorf("manual: %v %v", got, err)
	}
	stores["show State:/Network/Global/IPv4\n"] = "  No such key\n"
	if got, err := Physical(); err != nil || len(got) != 0 {
		t.Errorf("no network: %v %v", got, err)
	}
}
