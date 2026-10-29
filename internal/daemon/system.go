package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/kafeifei/xdial-next/internal/sysdns"
)

// System is what the daemon needs from macOS for DNS, ARCHITECTURE.md 6.4;
// tests replace it.
type System interface {
	// PhysicalDNS returns the DNS servers of the physical network.
	PhysicalDNS() ([]netip.Addr, error)
	// Hold publishes the resolver key in a session that inherits lock and
	// removes the key when it ends.
	Hold(key string, lock *os.File) (Resolver, error)
	// Resolver reports whether key is published and which server is the
	// first resolver of the system.
	Resolver(key string) (published bool, first string, err error)
	// Probe checks that a query to the resolver address reaches sing-box.
	Probe() error
	// FlushCache drops the system's DNS cache, so answers cached before the
	// resolver pointed into TUN do not outlive it, 3.3.
	FlushCache() error
}

// Resolver is a published resolver key.
type Resolver interface {
	Changes() <-chan struct{}
	Done() <-chan struct{}
	Republish() error
	Close()
}

var resolverAddress = netip.MustParseAddr(sysdns.Server)

type macOS struct{}

func (macOS) PhysicalDNS() ([]netip.Addr, error) { return sysdns.Physical() }

func (macOS) Hold(key string, lock *os.File) (Resolver, error) {
	return sysdns.Hold(key, resolverAddress, lock)
}

func (macOS) Resolver(key string) (bool, string, error) {
	published, err := sysdns.Present(key)
	if err != nil {
		return false, "", err
	}
	first, err := sysdns.FirstResolver()
	if err != nil {
		return published, "", err
	}
	return published, first, nil
}

func (macOS) Probe() error { return sysdns.Probe(resolverAddress, time.Second) }

func (macOS) FlushCache() error { return sysdns.FlushCache() }

// usablePhysical picks the servers the engine can dial directly: global
// addresses first, link-local ones only when there is nothing else.
func usablePhysical(servers []netip.Addr) []netip.Addr {
	var global, local []netip.Addr
	for _, s := range servers {
		switch {
		case !s.IsValid(), s.IsUnspecified(), s.IsLoopback(), s.IsMulticast():
		case s.IsLinkLocalUnicast():
			local = append(local, s)
		default:
			global = append(global, s)
		}
	}
	if len(global) > 0 {
		return global
	}
	return local
}

func sameServers(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func describeServers(servers []netip.Addr) string {
	if len(servers) == 0 {
		return "无"
	}
	return fmt.Sprint(servers)
}
