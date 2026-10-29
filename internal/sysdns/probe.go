package sysdns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/kafeifei/xdial-next/internal/netbind"
)

// ProbeName is answered NXDOMAIN by sing-box itself, without an upstream,
// ARCHITECTURE.md 6.4; asking it through TUN shows the path from the system
// to sing-box works.
const ProbeName = "_dns.resolver.arpa"

// Probe asks server for ProbeName over UDP and then TCP and expects
// NXDOMAIN both times: the route to the server enters TUN, hijack-dns takes
// the query and sing-box answers, 6.3. TCP matters because the mixed stack
// carries it on a different path than UDP.
func Probe(server netip.Addr, timeout time.Duration) error {
	return probeAt(netip.AddrPortFrom(server, 53), timeout)
}

func probeAt(server netip.AddrPort, timeout time.Duration) error {
	addr := server.String()
	d := &net.Dialer{Timeout: timeout}
	for _, network := range []string{"udp", "tcp"} {
		r, err := ask(d, network, addr, ProbeName, typeSVCB, timeout)
		if err == nil && r.rcode != rcodeNXDomain {
			err = fmt.Errorf("回复是 %s，应是 NXDOMAIN", rcodeName(r.rcode))
		}
		if err != nil {
			return fmt.Errorf("经 %s 问 %s：%w", network, addr, err)
		}
	}
	return nil
}

// UpstreamName is what Upstream asks: a name that always resolves.
const UpstreamName = "apple.com"

// Upstream asks server for UpstreamName's addresses from iface, outside
// TUN, and expects one: over UDP, and over TCP when the answer did not fit.
// Probe shows queries reach sing-box; this shows the physical network's
// DNS, which sing-box asks, resolves, ARCHITECTURE.md 7.
func Upstream(server netip.Addr, iface string, timeout time.Duration) error {
	return upstreamAt(netip.AddrPortFrom(server, 53), iface, timeout)
}

func upstreamAt(server netip.AddrPort, iface string, timeout time.Duration) error {
	d, err := netbind.Dialer(iface, timeout)
	if err != nil {
		return err
	}
	r, err := ask(d, "udp", server.String(), UpstreamName, typeA, timeout)
	if err == nil && r.truncated {
		r, err = ask(d, "tcp", server.String(), UpstreamName, typeA, timeout)
	}
	switch {
	case err != nil:
		return err
	case r.rcode != rcodeNoError:
		return fmt.Errorf("回复是 %s", rcodeName(r.rcode))
	case r.addresses == 0:
		return errors.New("回复里没有地址")
	}
	return nil
}

const (
	typeA    = 1
	typeSVCB = 64

	rcodeNoError  = 0
	rcodeNXDomain = 3
)

var rcodeNames = map[byte]string{0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

// answer is what ask reads from a reply.
type answer struct {
	rcode     byte
	truncated bool
	// addresses counts the A records among the answers.
	addresses int
}

// ask sends one query and reads the reply.
func ask(d *net.Dialer, network, addr, name string, qtype uint16, timeout time.Duration) (answer, error) {
	conn, err := d.Dial(network, addr)
	if err != nil {
		return answer{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	id := uint16(rand.Uint32())
	query := buildQuery(id, name, qtype)
	if network == "tcp" {
		query = append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)
	}
	if _, err := conn.Write(query); err != nil {
		return answer{}, err
	}
	reply := make([]byte, 4096)
	var n int
	if network == "tcp" {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return answer{}, err
		}
		length := int(binary.BigEndian.Uint16(size[:]))
		if length > len(reply) {
			return answer{}, errors.New("回复太长")
		}
		n, err = io.ReadFull(conn, reply[:length])
	} else {
		n, err = conn.Read(reply)
	}
	if err != nil {
		return answer{}, err
	}
	if n < 12 || binary.BigEndian.Uint16(reply) != id || reply[2]&0x80 == 0 {
		return answer{}, errors.New("回复不对")
	}
	return answer{rcode: reply[3] & 0x0f, truncated: reply[2]&0x02 != 0, addresses: countA(reply[:n])}, nil
}

// countA counts the A records among the answers of msg; what it cannot
// read counts as none.
func countA(msg []byte) int {
	questions := int(binary.BigEndian.Uint16(msg[4:]))
	answers := int(binary.BigEndian.Uint16(msg[6:]))
	at := 12
	// skipName steps over a name: labels up to the root, or a pointer.
	skipName := func() bool {
		for at < len(msg) {
			switch l := int(msg[at]); {
			case l == 0:
				at++
				return true
			case l&0xc0 == 0xc0:
				at += 2
				return at <= len(msg)
			default:
				at += 1 + l
			}
		}
		return false
	}
	for range questions {
		if !skipName() || at+4 > len(msg) {
			return 0
		}
		at += 4
	}
	count := 0
	for range answers {
		if !skipName() || at+10 > len(msg) {
			return count
		}
		typ, length := binary.BigEndian.Uint16(msg[at:]), int(binary.BigEndian.Uint16(msg[at+8:]))
		at += 10 + length
		if at > len(msg) {
			return count
		}
		if typ == typeA && length == 4 {
			count++
		}
	}
	return count
}

func rcodeName(rcode byte) string {
	if name, ok := rcodeNames[rcode]; ok {
		return name
	}
	return fmt.Sprintf("rcode %d", rcode)
}

// buildQuery encodes a recursive query for name and qtype, class IN.
func buildQuery(id uint16, name string, qtype uint16) []byte {
	msg := binary.BigEndian.AppendUint16(nil, id)
	msg = append(msg, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			msg = append(msg, byte(i-start))
			msg = append(msg, name[start:i]...)
			start = i + 1
		}
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	return append(msg, 0, 1)
}
