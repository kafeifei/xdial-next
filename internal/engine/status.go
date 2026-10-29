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
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/common/observable"
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
// line. A snapshot carries the status of every endpoint and group, by id;
// a line answering a url_test command carries only Test.
type StatusLine struct {
	Endpoints map[string]EndpointStatus `json:"endpoints,omitempty"`
	Groups    map[string]GroupStatus    `json:"groups,omitempty"`
	Test      *TestResult               `json:"test,omitempty"`
}

// GroupStatus is a group of lines as it runs: the member in use and what
// the last tests measured, ARCHITECTURE.md 3.6.
type GroupStatus struct {
	Type    string         `json:"type"`
	Now     string         `json:"now"`
	Members []MemberStatus `json:"members"`
}

// MemberStatus is one member of a group and its last test, if any.
type MemberStatus struct {
	Tag      string     `json:"tag"`
	DelayMS  int        `json:"delay_ms,omitempty"`
	TestedAt *time.Time `json:"tested_at,omitempty"`
}

// TestResult answers one url_test command.
type TestResult struct {
	ID      int                    `json:"id"`
	Results map[string]TestOutcome `json:"results"`
}

// TestOutcome is one line's test: a delay, or why there is none.
type TestOutcome struct {
	DelayMS int    `json:"delay_ms,omitempty"`
	Error   string `json:"error,omitempty"`
}

// probeAddresses ask an AnyConnect endpoint whether its routes take
// everything, 3.2, per address family: documentation addresses, which only
// a default route or one about as wide covers. Public addresses would
// mislead: sing-box adds a host route for each DNS server the VPN pushes,
// 1.1.1.1 included.
var probeAddresses = map[string]netip.Addr{"ipv4": netip.MustParseAddr("198.51.100.1"), "ipv6": netip.MustParseAddr("2001:db8::1")}

// statusInterval bounds how often the engine writes a status line.
const statusInterval = 500 * time.Millisecond

// reporter writes status lines to the daemon, 6.3.
type reporter struct {
	instance *box.Box
	history  *urltest.HistoryStorage
	writeMu  sync.Mutex
	encoder  *json.Encoder

	mu        sync.Mutex
	endpoints map[string]EndpointStatus
	changed   chan struct{}
}

func newReporter(instance *box.Box, history *urltest.HistoryStorage, w io.Writer) *reporter {
	return &reporter{instance: instance, history: history, encoder: json.NewEncoder(w),
		endpoints: map[string]EndpointStatus{}, changed: make(chan struct{}, 1)}
}

// poke asks for a new snapshot.
func (r *reporter) poke() {
	select {
	case r.changed <- struct{}{}:
	default:
	}
}

func (r *reporter) write(line StatusLine) error {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	return r.encoder.Encode(line)
}

// run writes a snapshot whenever an endpoint's or a group's status
// changes, at most every statusInterval and at least every groupInterval,
// until ctx ends.
func (r *reporter) run(ctx context.Context) {
	for _, e := range r.instance.Endpoint().Endpoints() {
		tag := e.Tag()
		set := func(s EndpointStatus) {
			r.mu.Lock()
			r.endpoints[tag] = s
			r.mu.Unlock()
			r.poke()
		}
		switch ep := e.(type) {
		case adapter.OpenConnectEndpoint:
			go watchOpenConnect(ctx, ep, set)
		case adapter.TailscaleEndpoint:
			go func() {
				_ = ep.SubscribeTailscaleStatus(ctx, func(st *adapter.TailscaleEndpointStatus) { set(tailscaleStatus(st)) })
			}()
		}
	}
	// Tests a group runs by itself land in the history.
	hook := observable.NewSubscriber[struct{}](8)
	r.history.AddUpdateHook(hook)
	go func() {
		updates, done := hook.Subscription()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-updates:
				r.poke()
			}
		}
	}()
	r.poke()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.changed:
		case <-time.After(groupInterval):
		}
		r.mu.Lock()
		line := StatusLine{Endpoints: make(map[string]EndpointStatus, len(r.endpoints)), Groups: r.groups()}
		for tag, s := range r.endpoints {
			line.Endpoints[tag] = s
		}
		r.mu.Unlock()
		if r.write(line) != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(statusInterval):
		}
	}
}

// groupInterval is how often a snapshot goes out regardless, so a group
// that switched by itself is seen.
const groupInterval = 15 * time.Second

func (r *reporter) groups() map[string]GroupStatus {
	out := map[string]GroupStatus{}
	for _, o := range r.instance.Outbound().Outbounds() {
		g, ok := o.(adapter.OutboundGroup)
		if !ok {
			continue
		}
		status := GroupStatus{Type: o.Type(), Now: g.Now(), Members: []MemberStatus{}}
		for _, tag := range g.All() {
			m := MemberStatus{Tag: tag}
			if h := r.history.LoadURLTestHistory(tag); h != nil {
				t := h.Time
				m.DelayMS, m.TestedAt = int(h.Delay), &t
			}
			status.Members = append(status.Members, m)
		}
		out[o.Tag()] = status
	}
	return out
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
// cannot push every line past the daemon's limit. The daemon keeps only
// the first 512 bytes, cut where no secret is split, so where this cut
// falls never matters.
const maxText = 64 << 10

func bound(s string) string {
	if len(s) <= maxText {
		return s
	}
	return strings.ToValidUTF8(s[:maxText], "")
}
