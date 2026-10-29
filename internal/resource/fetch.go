package resource

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/engine"
	"github.com/kafeifei/xdial-next/internal/netbind"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// FetchCommand is the hidden subcommand that downloads one remote resource
// in a process of its own, ARCHITECTURE.md 3.4. The daemon starts it as
// nobody; it holds only the line chain it downloads through.
const FetchCommand = "__fetch"

// Direct is the download_via of a resource downloaded without a line.
const Direct = "direct"

const maxRedirects = 5

// FetchRequest is what the daemon writes to the fetch child's stdin.
type FetchRequest struct {
	URL      string `json:"url"`
	MaxBytes int64  `json:"max_bytes"`
	Timeout  int64  `json:"timeout_ms"`
	// Interface is the physical interface every socket is bound to, so
	// a download goes around TUN while connected.
	Interface string `json:"interface"`
	// DNS is the physical network's DNS server, for downloads via direct.
	DNS string `json:"dns"`
	// Via is Direct or the tag of the outbound in Options to dial through.
	Via          string          `json:"via"`
	Options      json.RawMessage `json:"options,omitempty"`
	UserAgent    string          `json:"user_agent"`
	ETag         string          `json:"etag,omitempty"`
	LastModified string          `json:"last_modified,omitempty"`
}

// FetchResult is the child's first line on stdout; a body of Size bytes
// follows it when Code is empty and NotModified is false.
type FetchResult struct {
	Code         string `json:"code,omitempty"`
	Message      string `json:"message,omitempty"`
	NotModified  bool   `json:"not_modified,omitempty"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	Size         int64  `json:"size"`
}

// privileged reports whether this process runs as root, which the daemon
// never starts a download or decode child as.
func privileged() bool { return os.Geteuid() == 0 || os.Getuid() == 0 }

// blocked is a download the rules of 3.4 refuse, as opposed to one that
// failed.
type blocked struct{ reason string }

func (b *blocked) Error() string { return b.reason }

// RunFetchChild reads one FetchRequest from stdin, downloads it and writes
// a FetchResult line and the body to stdout.
func RunFetchChild(stdin io.Reader, stdout io.Writer) int {
	if privileged() {
		return writeResult(stdout, FetchResult{Code: cli.CodeInternal, Message: "下载子进程不能以 root 运行"}, nil)
	}
	var req FetchRequest
	if err := json.NewDecoder(io.LimitReader(stdin, 16<<20)).Decode(&req); err != nil {
		return writeResult(stdout, FetchResult{Code: cli.CodeInternal, Message: "读不到下载请求"}, nil)
	}
	timeout := time.Duration(req.Timeout) * time.Millisecond
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	body, result := fetch(ctx, req)
	return writeResult(stdout, result, body)
}

func writeResult(stdout io.Writer, result FetchResult, body []byte) int {
	w := bufio.NewWriter(stdout)
	result.Size = int64(len(body))
	line, _ := json.Marshal(result)
	_, _ = w.Write(append(line, '\n'))
	_, _ = w.Write(body)
	if err := w.Flush(); err != nil || result.Code != "" {
		return 1
	}
	return 0
}

func fetch(ctx context.Context, req FetchRequest) ([]byte, FetchResult) {
	target, err := url.Parse(req.URL)
	if err != nil || target.Scheme != "https" || target.Host == "" {
		return nil, FetchResult{Code: cli.CodeResourceBlocked, Message: "地址不是 https"}
	}
	dial, closeDialer, err := dialerFor(ctx, req)
	if err != nil {
		return nil, FetchResult{Code: cli.CodeResourceDownload, Message: err.Error()}
	}
	defer closeDialer()
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dial,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: testRoots},
		TLSHandshakeTimeout:    15 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		// Every hop must be https; the dialer checks where each one goes.
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if next.URL.Scheme != "https" {
				return &blocked{"重定向到了不是 https 的地址"}
			}
			if len(via) >= maxRedirects {
				return &tooManyRedirects{}
			}
			return nil
		},
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, FetchResult{Code: cli.CodeResourceBlocked, Message: "地址不合法"}
	}
	if req.UserAgent != "" {
		httpReq.Header.Set("User-Agent", req.UserAgent)
	}
	if req.ETag != "" {
		httpReq.Header.Set("If-None-Match", req.ETag)
	}
	if req.LastModified != "" {
		httpReq.Header.Set("If-Modified-Since", req.LastModified)
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, failure(err)
	}
	defer resp.Body.Close()
	result := FetchResult{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	switch {
	case resp.StatusCode == http.StatusNotModified && (req.ETag != "" || req.LastModified != ""):
		result.NotModified = true
		return nil, result
	case resp.StatusCode != http.StatusOK:
		// The status only: the body is remote content and is never echoed.
		return nil, FetchResult{Code: cli.CodeResourceDownload, Message: "服务器返回 HTTP " + strconv.Itoa(resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, req.MaxBytes+1))
	if err != nil {
		return nil, failure(err)
	}
	if int64(len(body)) > req.MaxBytes {
		return nil, FetchResult{Code: cli.CodeResourceTooLarge, Message: fmt.Sprintf("内容超过 %d 字节", req.MaxBytes)}
	}
	return body, result
}

// failure describes a failed request in words of XDial's own: the
// underlying error text can carry the URL, a redirect's Location or a
// server's name, any of which may hold a subscription token.
func failure(err error) FetchResult {
	var b *blocked
	if errors.As(err, &b) {
		return FetchResult{Code: cli.CodeResourceBlocked, Message: b.reason}
	}
	var (
		netErr     net.Error
		dnsErr     *net.DNSError
		opErr      *net.OpError
		certErr    *tls.CertificateVerificationError
		hostErr    x509.HostnameError
		authErr    x509.UnknownAuthorityError
		invalidErr x509.CertificateInvalidError
		recordErr  tls.RecordHeaderError
		redirects  *tooManyRedirects
	)
	message := "下载失败"
	switch {
	case errors.As(err, &redirects):
		message = fmt.Sprintf("重定向超过 %d 次", maxRedirects)
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		message = "下载超时"
	case errors.As(err, &dnsErr):
		message = "解析服务器的域名失败"
	case errors.As(err, &certErr), errors.As(err, &hostErr), errors.As(err, &authErr), errors.As(err, &invalidErr):
		message = "服务器的证书不受信任"
	case errors.As(err, &recordErr):
		message = "TLS 握手失败"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		message = "连不上服务器"
	}
	return FetchResult{Code: cli.CodeResourceDownload, Message: message}
}

type tooManyRedirects struct{}

func (*tooManyRedirects) Error() string { return "too many redirects" }

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// dialerFor returns how the download reaches the server: directly, with
// every address it resolves to checked first, or through a line, whose
// server makes the connection on its own side.
func dialerFor(ctx context.Context, req FetchRequest) (dialFunc, func(), error) {
	if req.Via == Direct || req.Via == "" {
		dial, err := directDialer(req.Interface, req.DNS)
		return dial, func() {}, err
	}
	boxCtx := engine.Context(ctx)
	var opts option.Options
	if err := opts.UnmarshalJSONContext(boxCtx, req.Options); err != nil {
		return nil, nil, errors.New("下载线路的配置不对")
	}
	opts.Log = &option.LogOptions{Disabled: true}
	instance, err := box.New(box.Options{Context: boxCtx, Options: opts})
	if err != nil {
		return nil, nil, errors.New("下载线路起不来")
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, nil, errors.New("下载线路起不来")
	}
	out, ok := instance.Outbound().Outbound(req.Via)
	if !ok {
		_ = instance.Close()
		return nil, nil, fmt.Errorf("下载线路 %s 不存在", req.Via)
	}
	dial := func(ctx context.Context, _, address string) (net.Conn, error) {
		return out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
	}
	return dial, func() { _ = instance.Close() }, nil
}

// directDialer resolves with the physical network's DNS and dials only
// addresses Allowed accepts, every socket bound to iface.
func directDialer(iface, dns string) (dialFunc, error) {
	server, err := netip.ParseAddr(dns)
	if err != nil {
		return nil, errors.New("没有物理网络的 DNS")
	}
	base, err := boundDialer(iface)
	if err != nil {
		return nil, err
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return base.DialContext(ctx, network, netip.AddrPortFrom(server, 53).String())
		},
	}
	return func(ctx context.Context, _, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return nil, err
		}
		var candidates []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			candidates = []netip.Addr{ip}
		} else if candidates, err = resolver.LookupNetIP(ctx, "ip", host); err != nil {
			return nil, err
		}
		var lastErr error = &blocked{"服务器的地址都在本机或内网，不允许下载"}
		for _, ip := range candidates {
			if !allowed(ip) {
				continue
			}
			conn, err := base.DialContext(ctx, "tcp", netip.AddrPortFrom(ip.Unmap(), uint16(port)).String())
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}, nil
}

func boundDialer(iface string) (*net.Dialer, error) {
	return netbind.Dialer(iface, 15*time.Second)
}

// Seams for tests, which serve on loopback with their own certificate.
var (
	allowed   = Allowed
	testRoots *x509.CertPool
)

// Address ranges a direct download must not reach, ARCHITECTURE.md 3.4:
// the machine itself and networks behind it, including the tailnet's
// CGNAT range, and ranges no public server lives in.
var refused = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fec0::/10"),
}

// Embedding prefixes whose low 32 bits are an IPv4 address that is checked
// in turn: NAT64 and 6to4.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")
var sixToFour = netip.MustParsePrefix("2002::/16")

// Allowed reports whether a direct download may connect to ip.
func Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if ip.Is4() && ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	for _, p := range refused {
		if p.Contains(ip) {
			return false
		}
	}
	if nat64.Contains(ip) {
		b := ip.As16()
		return Allowed(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	if sixToFour.Contains(ip) {
		b := ip.As16()
		return Allowed(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
	}
	return true
}
