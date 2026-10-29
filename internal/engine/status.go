package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
)

// EndpointStatus is what the engine reports about one endpoint line after
// it is ready, ARCHITECTURE.md 6.3. sing-box brings endpoints up in the
// background, so the engine being ready says nothing about them.
type EndpointStatus struct {
	Type string `json:"type"`
	// State is connecting, connected, auth_required or failed.
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	// AnyConnect.
	AuthMessage  string     `json:"auth_message,omitempty"`
	BrowserAuth  bool       `json:"browser_auth,omitempty"`
	Addresses    []string   `json:"addresses,omitempty"`
	DNS          []string   `json:"dns,omitempty"`
	DefaultRoute []string   `json:"default_route,omitempty"` // the families, ipv4 and ipv6
	Since        *time.Time `json:"since,omitempty"`
	// Tailscale.
	AuthURL  string   `json:"auth_url,omitempty"`
	Tailnet  string   `json:"tailnet,omitempty"`
	DNSName  string   `json:"dns_name,omitempty"`
	ExitNode string   `json:"exit_node,omitempty"`
	Peers    int      `json:"peers,omitempty"`
	Online   int      `json:"online,omitempty"`
	Self     []string `json:"self,omitempty"`
}

// StatusLine is one line the engine writes to stdout after its ready
// line: the status of every endpoint, by line id.
type StatusLine struct {
	Endpoints map[string]EndpointStatus `json:"endpoints"`
}

// statusInterval bounds how often the engine writes a status line.
const statusInterval = 500 * time.Millisecond

// probeAddresses ask an AnyConnect endpoint whether its routes take
// everything, 3.2, per address family: documentation addresses, which only
// a default route or one about as wide covers. Public addresses would
// mislead: sing-box adds a host route for each DNS server the VPN pushes,
// 1.1.1.1 included.
var probeAddresses = map[string]netip.Addr{"ipv4": netip.MustParseAddr("198.51.100.1"), "ipv6": netip.MustParseAddr("2001:db8::1")}

// reportEndpoints writes a StatusLine to w whenever an endpoint's status
// changes, at most every statusInterval, until ctx ends.
func reportEndpoints(ctx context.Context, instance *box.Box, w io.Writer) {
	var mu sync.Mutex
	statuses := map[string]EndpointStatus{}
	changed := make(chan struct{}, 1)
	set := func(tag string, s EndpointStatus) {
		mu.Lock()
		statuses[tag] = s
		mu.Unlock()
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	for _, e := range instance.Endpoint().Endpoints() {
		switch ep := e.(type) {
		case adapter.OpenConnectEndpoint:
			go watchOpenConnect(ctx, ep, func(s EndpointStatus) { set(e.Tag(), s) })
		case adapter.TailscaleEndpoint:
			go func() {
				_ = ep.SubscribeTailscaleStatus(ctx, func(st *adapter.TailscaleEndpointStatus) { set(e.Tag(), tailscaleStatus(st)) })
			}()
		}
	}
	encoder := json.NewEncoder(w)
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
		mu.Lock()
		line := StatusLine{Endpoints: make(map[string]EndpointStatus, len(statuses))}
		for tag, s := range statuses {
			line.Endpoints[tag] = s
		}
		mu.Unlock()
		if encoder.Encode(line) != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(statusInterval):
		}
	}
}

func watchOpenConnect(ctx context.Context, ep adapter.OpenConnectEndpoint, report func(EndpointStatus)) {
	for {
		updated := ep.StatusUpdated()
		report(openConnectStatus(ep))
		select {
		case <-ctx.Done():
			return
		case <-updated:
		case <-time.After(10 * time.Second):
			// The client's readiness changes without a notification.
		}
	}
}

func openConnectStatus(ep adapter.OpenConnectEndpoint) EndpointStatus {
	st := ep.OpenConnectStatus()
	s := EndpointStatus{Type: "openconnect", Error: bound(st.Error)}
	switch st.State {
	case adapter.OpenConnectStateConnected:
		s.State = "connected"
	case adapter.OpenConnectStateAuthPending:
		s.State = "auth_required"
	case adapter.OpenConnectStateError:
		s.State = "failed"
	default:
		s.State = "connecting"
	}
	if c := st.AuthChallenge; c != nil {
		s.AuthMessage = bound(strings.TrimSpace(strings.Join([]string{c.Message, c.Error}, " ")))
		s.BrowserAuth = c.Browser != nil
	}
	if t := st.TunnelInfo; t != nil {
		for _, p := range append(append([]netip.Prefix{}, t.IPv4...), t.IPv6...) {
			s.Addresses = append(s.Addresses, p.String())
		}
		for _, a := range t.DNS {
			s.DNS = append(s.DNS, a.String())
		}
		since := t.ConnectedSince
		s.Since = &since
		if preferred, ok := ep.(adapter.OutboundWithPreferredRoutes); ok {
			for _, family := range []string{"ipv4", "ipv6"} {
				if preferred.PreferredAddress(&adapter.InboundContext{}, probeAddresses[family]) {
					s.DefaultRoute = append(s.DefaultRoute, family)
				}
			}
		}
	}
	return s
}

func tailscaleStatus(st *adapter.TailscaleEndpointStatus) EndpointStatus {
	s := EndpointStatus{Type: "tailscale", Tailnet: st.NetworkName}
	switch st.BackendState {
	case "Running":
		s.State = "connected"
	case "NeedsLogin", "NeedsMachineAuth":
		s.State = "auth_required"
		s.AuthURL = st.AuthURL
	default:
		s.State = "connecting"
	}
	if st.Self != nil {
		s.DNSName = st.Self.DNSName
		s.Self = append(s.Self, st.Self.TailscaleIPs...)
	}
	if st.ExitNode != nil {
		s.ExitNode = st.ExitNode.HostName
	}
	for _, g := range st.UserGroups {
		for _, p := range g.Peers {
			s.Peers++
			if p.Online {
				s.Online++
			}
		}
	}
	sort.Strings(s.Self)
	return s
}

// maxText bounds a VPN server's text in a status line, so one endpoint
// cannot push every line past the daemon's limit. It is far above what the
// daemon keeps after scrubbing, 512 bytes, so a secret this cut splits is
// beyond what is kept, and the daemon still scrubs whole secrets first.
const maxText = 64 << 10

func bound(s string) string {
	if len(s) <= maxText {
		return s
	}
	return strings.ToValidUTF8(s[:maxText], "")
}
