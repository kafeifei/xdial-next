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
	return serveDNSWith(t, func(q []byte, _ bool) []byte { return reply(q, rcode, 0, false) })
}

// reply answers q with rcode and as many A records for its name.
func reply(q []byte, rcode byte, records int, truncated bool) []byte {
	r := append([]byte(nil), q...)
	r[2] |= 0x80
	if truncated {
		r[2] |= 0x02
	}
	r[3] = r[3]&0xf0 | rcode
	binary.BigEndian.PutUint16(r[6:], uint16(records))
	for range records {
		// The question's name by pointer, A, IN, a TTL, 192.0.2.1.
		r = append(r, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1)
	}
	return r
}

// serveDNSWith answers queries over UDP and TCP on loopback with answer.
func serveDNSWith(t *testing.T, answer func(q []byte, tcp bool) []byte) netip.AddrPort {
	t.Helper()
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
			_, _ = pc.WriteTo(answer(buf[:n], false), from)
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
					r := answer(q, true)
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
	q := buildQuery(0x1234, ProbeName, typeSVCB)
	if binary.BigEndian.Uint16(q) != 0x1234 || !strings.HasSuffix(string(q), "\x04_dns\x08resolver\x04arpa\x00\x00\x40\x00\x01") {
		t.Errorf("query % x", q)
	}
}

func TestUpstream(t *testing.T) {
	lo := ""
	interfaces, _ := net.Interfaces()
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback != 0 {
			lo = i.Name
		}
	}
	for name, tc := range map[string]struct {
		answer func(q []byte, tcp bool) []byte
		ok     bool
	}{
		"an address":   {func(q []byte, _ bool) []byte { return reply(q, 0, 1, false) }, true},
		"no address":   {func(q []byte, _ bool) []byte { return reply(q, 0, 0, false) }, false},
		"SERVFAIL":     {func(q []byte, _ bool) []byte { return reply(q, 2, 0, false) }, false},
		"NXDOMAIN":     {func(q []byte, _ bool) []byte { return reply(q, 3, 0, false) }, false},
		"over TCP":     {func(q []byte, tcp bool) []byte { return reply(q, 0, map[bool]int{true: 1}[tcp], !tcp) }, true},
		"cut, no more": {func(q []byte, tcp bool) []byte { return reply(q, 0, 0, !tcp) }, false},
	} {
		err := upstreamAt(serveDNSWith(t, tc.answer), lo, time.Second)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := upstreamAt(netip.MustParseAddrPort("127.0.0.1:1"), "", time.Second); err == nil {
		t.Error("no interface passed")
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

func TestSupplementals(t *testing.T) {
	out := `DNS configuration

resolver #1
  search domain[0] : attlocal.net
  nameserver[0] : 192.168.1.254
  if_index : 17 (en0)
  flags    : Request A records

resolver #2
  domain   : corp.example
  nameserver[0] : 10.0.0.53
  nameserver[1] : fe80::1%utun4
  if_index : 23 (utun4)
  flags    : Supplemental, Request A records

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5

resolver #4
  domain   : test
  nameserver[0] : 127.0.0.1
  port     : 5353

DNS configuration (for scoped queries)

resolver #1
  domain   : scoped.example
  nameserver[0] : 192.168.1.254
  if_index : 17 (en0)
`
	got := parseSupplementals(out)
	want := []Supplemental{
		{Domain: "corp.example", Servers: []string{"10.0.0.53", "fe80::1%utun4"}, Interface: "utun4"},
		{Domain: "test", Servers: []string{"127.0.0.1"}, Port: 5353},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v", got)
	}
}

func TestConnectedVPNs(t *testing.T) {
	out := `Available network connection services in the current set (*=enabled):
* (Disconnected)   1236708A-F972-49BE-B675-F9B3FE374FB2 VPN (io.tailscale.ipn.macsys) "Tailscale"                      [VPN:io.tailscale.ipn.macsys]
* (Connected)      2236708A-F972-49BE-B675-F9B3FE374FB2 VPN (com.cisco.anyconnect) "Corp VPN"   [VPN:com.cisco.anyconnect]
  (Connected)      3236708A-F972-49BE-B675-F9B3FE374FB2 PPP --> L2TP "Old"   [PPP:L2TP]
`
	if got := parseConnectedVPNs(out); fmt.Sprint(got) != "[Corp VPN Old]" {
		t.Errorf("got %v", got)
	}
	if !IsTunnel("utun4") || IsTunnel("en0") {
		t.Error("IsTunnel")
	}
}
