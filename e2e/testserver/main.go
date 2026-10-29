// Command testserver runs a sing-box server in the e2e virtual machine, so
// proxy lines and subscriptions have something to connect to without real
// credentials, docs/plan.md section 6. It is built only for e2e and never
// shipped; it takes a sing-box configuration file and runs until killed.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
)

// serverContext registers the server side of the protocols e2e uses, and
// nothing else: upstream's include package needs modules XDial does not
// depend on.
func serverContext() context.Context {
	inbounds := inbound.NewRegistry()
	shadowsocks.RegisterInbound(inbounds)
	vmess.RegisterInbound(inbounds)
	vless.RegisterInbound(inbounds)
	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	resolvers := dns.NewTransportRegistry()
	transport.RegisterUDP(resolvers)
	return box.Context(context.Background(), inbounds, outbounds, endpoint.NewRegistry(), resolvers, service.NewRegistry(), certificate.NewRegistry())
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: testserver <config.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx := serverContext()
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err == nil {
		err = instance.Start()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	<-signals
	_ = instance.Close()
}
