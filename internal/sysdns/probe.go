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
	for _, network := range []string{"udp", "tcp"} {
		if err := probe(network, addr, timeout); err != nil {
			return fmt.Errorf("经 %s 问 %s：%w", network, addr, err)
		}
	}
	return nil
}

func probe(network, addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	id := uint16(rand.Uint32())
	query := buildQuery(id, ProbeName)
	if network == "tcp" {
		query = append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)
	}
	if _, err := conn.Write(query); err != nil {
		return err
	}
	reply := make([]byte, 4096)
	var n int
	if network == "tcp" {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint16(size[:]))
		if length > len(reply) {
			return errors.New("回复太长")
		}
		n, err = io.ReadFull(conn, reply[:length])
	} else {
		n, err = conn.Read(reply)
	}
	if err != nil {
		return err
	}
	if n < 12 || binary.BigEndian.Uint16(reply) != id || reply[2]&0x80 == 0 {
		return errors.New("回复不对")
	}
	if rcode := reply[3] & 0x0f; rcode != 3 {
		return fmt.Errorf("rcode %d，应是 NXDOMAIN", rcode)
	}
	return nil
}

// buildQuery encodes a recursive query for name, type SVCB, class IN.
func buildQuery(id uint16, name string) []byte {
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
	msg = append(msg, 0, 0, 64, 0, 1)
	return msg
}
