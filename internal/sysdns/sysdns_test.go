package sysdns

import (
	"encoding/binary"
	"fmt"
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

// fakeStore answers scutil shows from a map, as scutil prints them.
func fakeStore(t *testing.T, stores map[string]string) {
	t.Helper()
	previous := Runner
	t.Cleanup(func() { Runner = previous })
	Runner = func(script string, _ ...string) (string, error) {
		var out strings.Builder
		for _, line := range strings.Split(strings.TrimSpace(script), "\n") {
			key := strings.TrimPrefix(line, "show ")
			if v, ok := stores[key]; ok {
				out.WriteString(v)
			} else {
				out.WriteString("  No such key\n")
			}
		}
		return out.String(), nil
	}
}

func dict(lines ...string) string {
	return "<dictionary> {\n" + strings.Join(lines, "\n") + "\n}\n"
}

func servers(addrs ...string) string {
	s := "  ServerAddresses : <array> {\n"
	for i, a := range addrs {
		s += fmt.Sprintf("    %d : %s\n", i, a)
	}
	return s + "  }"
}

const v4 = "  Addresses : <array> {\n    0 : 192.168.64.2\n  }"

func TestPhysical(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stores map[string]string
		want   string
	}{
		{"dhcp", map[string]string{
			"State:/Network/Global/IPv4":    dict("  PrimaryService : A"),
			"State:/Network/Service/A/DNS":  dict(servers("192.168.64.1")),
			"State:/Network/Service/A/IPv4": dict(v4),
		}, "[192.168.64.1]"},
		{"manual wins", map[string]string{
			"State:/Network/Global/IPv4":    dict("  PrimaryService : A"),
			"Setup:/Network/Service/A/DNS":  dict(servers("223.5.5.5")),
			"State:/Network/Service/A/DNS":  dict(servers("192.168.64.1")),
			"State:/Network/Service/A/IPv4": dict(v4),
		}, "[223.5.5.5]"},
		{"no network", map[string]string{}, "[]"},
		{"ipv4 primary without dns, ipv6 primary with", map[string]string{
			"State:/Network/Global/IPv4":    dict("  PrimaryService : A"),
			"State:/Network/Global/IPv6":    dict("  PrimaryService : B"),
			"State:/Network/Service/A/IPv4": dict(v4),
			"State:/Network/Service/B/DNS":  dict(servers("2001:db8::53")),
			"State:/Network/Service/B/IPv6": dict("  Addresses : <array> {\n    0 : 2001:db8::2\n  }"),
		}, "[2001:db8::53]"},
		{"filtered manual servers fall back to dhcp", map[string]string{
			"State:/Network/Global/IPv4":    dict("  PrimaryService : A"),
			"Setup:/Network/Service/A/DNS":  dict(servers("2606:4700:4700::1111")),
			"State:/Network/Service/A/DNS":  dict(servers("192.168.64.1")),
			"State:/Network/Service/A/IPv4": dict(v4),
		}, "[192.168.64.1]"},
		{"link-local server gets its interface", map[string]string{
			"State:/Network/Global/IPv6":    dict("  PrimaryService : B"),
			"State:/Network/Service/B/DNS":  dict(servers("fe80::1")),
			"State:/Network/Service/B/IPv6": dict("  Addresses : <array> {\n    0 : fe80::2\n  }", "  InterfaceName : en0"),
		}, "[fe80::1%en0]"},
		{"manual ipv4 dns on an ipv6-only service", map[string]string{
			"State:/Network/Global/IPv6":    dict("  PrimaryService : B"),
			"Setup:/Network/Service/B/DNS":  dict(servers("1.1.1.1", "2606:4700:4700::1111")),
			"State:/Network/Service/B/IPv6": dict("  Addresses : <array> {\n    0 : 2001:db8::2\n  }"),
		}, "[2606:4700:4700::1111]"},
	} {
		fakeStore(t, tc.stores)
		got, err := Physical()
		if err != nil || fmt.Sprint(got) != tc.want {
			t.Errorf("%s: %v %v, want %s", tc.name, got, err, tc.want)
		}
	}
}

func TestSplitBlocks(t *testing.T) {
	out := dict("  A : <dictionary> {", "    B : 1", "  }") + "  No such key\n" + dict("  C : 2")
	if blocks := splitBlocks(out); len(blocks) != 3 || blocks[1] != "" || !strings.Contains(blocks[0], "B : 1") {
		t.Errorf("blocks %q", blocks)
	}
}
