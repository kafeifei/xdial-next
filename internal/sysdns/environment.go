package sysdns

import (
	"regexp"
	"strconv"
	"strings"
)

// Supplemental is a resolver the system asks instead of the first one for
// names in its domain: another VPN's split DNS, a file in /etc/resolver.
// Queries for those names do not reach XDial, ARCHITECTURE.md 6.4.
type Supplemental struct {
	Domain  string   `json:"domain"`
	Servers []string `json:"servers"`
	// Port is the servers' port when it is not 53.
	Port      int    `json:"port,omitempty"`
	Interface string `json:"interface,omitempty"`
}

// Supplementals reads scutil --dns. mDNS resolvers, which answer on the
// local link only, are left out.
func Supplementals() ([]Supplemental, error) {
	out, err := Runner("", "--dns")
	if err != nil {
		return nil, err
	}
	return parseSupplementals(out), nil
}

func parseSupplementals(out string) []Supplemental {
	// The second section lists the resolvers of scoped queries.
	out, _, _ = strings.Cut(out, "DNS configuration (for scoped queries)")
	var list []Supplemental
	for _, block := range strings.Split(out, "\nresolver #")[1:] {
		var s Supplemental
		mdns := false
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			switch {
			case key == "domain":
				s.Domain = value
			case strings.HasPrefix(key, "nameserver["):
				s.Servers = append(s.Servers, value)
			case key == "if_index":
				if _, name, ok := strings.Cut(value, "("); ok {
					s.Interface = strings.TrimSuffix(name, ")")
				}
			case key == "port":
				if port, err := strconv.Atoi(value); err == nil && port != 53 {
					s.Port = port
				}
			case key == "options":
				mdns = strings.Contains(value, "mdns")
			}
		}
		if s.Domain != "" && !mdns {
			list = append(list, s)
		}
	}
	return list
}

// ConnectedVPNs reads scutil --nc list: the names of the VPN services that
// are connected.
func ConnectedVPNs() ([]string, error) {
	out, err := Runner("", "--nc", "list")
	if err != nil {
		return nil, err
	}
	return parseConnectedVPNs(out), nil
}

var connectedService = regexp.MustCompile(`\(Connected\).*?"([^"]*)"`)

func parseConnectedVPNs(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if m := connectedService.FindStringSubmatch(line); m != nil {
			names = append(names, m[1])
		}
	}
	return names
}

// IsTunnel reports whether iface is a tunnel: when the primary network
// service is on one, another VPN carries the system's traffic.
func IsTunnel(iface string) bool {
	for _, prefix := range []string{"utun", "ipsec", "ppp", "tun", "tap"} {
		if strings.HasPrefix(iface, prefix) {
			return true
		}
	}
	return false
}
