package engine

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/openconnect"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/tailscale"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
)

// Context returns a context whose registries hold only the types the allow
// list admits and the ones XDial's generated configuration needs,
// ARCHITECTURE.md 2.3. Upstream's include package also registers tor,
// bridge, snell and services such as api and ssmapi; leaving it out keeps
// them out of reach entirely. No service is registered. The context also
// carries the second line of defense of guard.go; allowed lists the only
// directories sing-box may touch.
func Context(ctx context.Context, allowed ...string) context.Context {
	inbounds := inbound.NewRegistry()
	tun.RegisterInbound(inbounds)
	mixed.RegisterInbound(inbounds)

	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	group.RegisterSelector(outbounds)
	group.RegisterURLTest(outbounds)
	shadowsocks.RegisterOutbound(outbounds)
	vmess.RegisterOutbound(outbounds)
	vless.RegisterOutbound(outbounds)
	trojan.RegisterOutbound(outbounds)
	anytls.RegisterOutbound(outbounds)

	endpoints := endpoint.NewRegistry()
	openconnect.RegisterEndpoint(endpoints)
	tailscale.RegisterEndpoint(endpoints)

	resolvers := dns.NewTransportRegistry()
	transport.RegisterUDP(resolvers)
	transport.RegisterHTTPS(resolvers)
	openconnect.RegisterDNSTransport(resolvers)
	tailscale.RegistryTransport(resolvers)

	return box.Context(guard(ctx, allowed...), inbounds, outbounds, endpoints, resolvers, service.NewRegistry(), certificate.NewRegistry())
}
