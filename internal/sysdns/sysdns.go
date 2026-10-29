// Package sysdns points the system resolver into TUN while connected and
// reads the physical network's DNS, ARCHITECTURE.md 6.4. The resolver key is
// a temporary value of a scutil session the daemon keeps open: configd
// removes it when that session ends, however the daemon ends, so the system
// is never left pointed at a TUN that is gone. Everything goes through
// /usr/sbin/scutil, so the daemon needs no cgo.
package sysdns

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Server is the resolver address inside TUN; queries to it enter TUN and
// are hijacked into sing-box.
const Server = "172.19.0.2"

// The physical network's DNS is read from the primary service's own keys:
// configd's State:/Network/Global/DNS follows the first resolver, which is
// XDial's while connected (measured 2026-10-28).
const (
	primaryIPv4 = "State:/Network/Global/IPv4"
	primaryIPv6 = "State:/Network/Global/IPv6"
)

const scutil = "/usr/sbin/scutil"

var keyPattern = regexp.MustCompile(`^State:/Network/Service/[A-Za-z0-9.\-]+/DNS$`)

// Session is a running scutil that holds the resolver key and reports
// changes to it and to the physical DNS.
type Session struct {
	key       string
	cmd       *exec.Cmd
	writeMu   sync.Mutex
	stdin     *os.File
	closeOnce sync.Once
	done      chan struct{}
	changes   chan struct{}
}

// Time limits, so a stuck scutil or configd cannot hold up the daemon.
const (
	commandTimeout = 5 * time.Second
	writeTimeout   = 2 * time.Second
	closeTimeout   = 3 * time.Second
)

// Hold starts a session that adds key as a temporary value pointing at
// server for every domain, then watches what the physical DNS is read
// from, and every service's DNS, key included. The session inherits extra,
// the connection lock of 6.1, so the lock outlives the daemon until the
// key is gone.
func Hold(key string, server netip.Addr, extra ...*os.File) (*Session, error) {
	if !keyPattern.MatchString(key) {
		return nil, fmt.Errorf("sysdns: bad key %q", key)
	}
	// A pipe of our own, not StdinPipe, so writes can have a deadline.
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(scutil)
	cmd.Stdin = r
	cmd.ExtraFiles = extra
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		r.Close()
		w.Close()
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	err = cmd.Start()
	r.Close()
	if err != nil {
		w.Close()
		return nil, err
	}
	s := &Session{key: key, cmd: cmd, stdin: w, done: make(chan struct{}), changes: make(chan struct{}, 1)}
	go func() {
		// Notifications and errors are the only output; any line means
		// something may have changed, and the daemon reads the store again.
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case s.changes <- struct{}{}:
			default:
			}
		}
	}()
	go func() {
		_ = cmd.Wait()
		s.closeOnce.Do(func() { _ = s.stdin.Close() })
		close(s.done)
	}()
	script := fmt.Sprintf("d.init\nd.add ServerAddresses * %s\nd.add SupplementalMatchDomains * \"\"\nadd %s temporary\n"+
		"n.add %s\nn.add %s\nn.add State:/Network/Service/[^/]+/DNS pattern\nn.add Setup:/Network/Service/[^/]+/DNS pattern\nn.watch\n",
		server, key, primaryIPv4, primaryIPv6)
	if err := s.write(script); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) write(script string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.stdin.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := io.WriteString(s.stdin, script)
	return err
}

// Republish adds the key again, for when configd lost it (a configd
// restart drops every key). The current dictionary of the session is still
// the resolver's: notifications do not change it.
func (s *Session) Republish() error {
	return s.write(fmt.Sprintf("add %s temporary\n", s.key))
}

// Changes receives a value when the key or the physical DNS may have
// changed.
func (s *Session) Changes() <-chan struct{} { return s.changes }

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Close ends the session, which removes the key, and waits for it. It does
// not wait for a write in progress: closing the pipe ends that write too,
// and a session that does not exit is killed.
func (s *Session) Close() {
	s.closeOnce.Do(func() { _ = s.stdin.Close() })
	select {
	case <-s.done:
	case <-time.After(closeTimeout):
		_ = s.cmd.Process.Kill()
		<-s.done
	}
}

// Runner executes scutil with a script on stdin and returns its output,
// within commandTimeout; tests replace it.
var Runner = func(script string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, scutil, args...)
	cmd.WaitDelay = time.Second
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("scutil: %v: %s", err, out.String())
	}
	return out.String(), nil
}

// Present reports whether key is in the dynamic store.
func Present(key string) (bool, error) {
	out, err := Runner(fmt.Sprintf("show %s\n", key))
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "ServerAddresses"), nil
}

// Physical returns the DNS servers of the physical network, close to how
// configd picks the default resolver: the primary services for IPv4 and
// IPv6, each with servers set by hand (Setup:) winning over those from DHCP
// or router advertisements (State:), keeping only the address families the
// service has an address in; the first service left with servers wins.
func Physical() ([]netip.Addr, error) {
	globals, err := showAll(primaryIPv4, primaryIPv6)
	if err != nil {
		return nil, err
	}
	var services []string
	for _, g := range globals {
		service := parseValue(g, "PrimaryService")
		if service != "" && !strings.ContainsAny(service, " \n/") && !slices.Contains(services, service) {
			services = append(services, service)
		}
	}
	for _, service := range services {
		base := "/Network/Service/" + service + "/"
		blocks, err := showAll("Setup:"+base+"DNS", "State:"+base+"DNS", "State:"+base+"IPv4", "State:"+base+"IPv6")
		if err != nil {
			return nil, err
		}
		v4, v6 := hasAddresses(blocks[2]), hasAddresses(blocks[3])
		iface := parseValue(blocks[3], "InterfaceName")
		if iface == "" {
			iface = parseValue(blocks[2], "InterfaceName")
		}
		usable := func(block string) []netip.Addr {
			var out []netip.Addr
			for _, a := range parseServers(block) {
				if a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "" && iface != "" {
					// A link-local server is only reachable on its interface.
					a = a.WithZone(iface)
				}
				if (a.Is4() && v4) || (a.Is6() && v6) {
					out = append(out, a)
				}
			}
			return out
		}
		// Each source is filtered first, as configd does: hand-set servers
		// of a family the service lacks do not hide the ones from DHCP.
		if servers := usable(blocks[0]); len(servers) > 0 {
			return servers, nil
		}
		if servers := usable(blocks[1]); len(servers) > 0 {
			return servers, nil
		}
	}
	return nil, nil
}

func hasAddresses(block string) bool {
	return strings.Contains(block, "Addresses : <array>")
}

// showAll shows several keys in one scutil run and returns one block per
// key, empty for a key that does not exist.
func showAll(keys ...string) ([]string, error) {
	var script strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&script, "show %s\n", k)
	}
	out, err := Runner(script.String())
	if err != nil {
		return nil, err
	}
	blocks := splitBlocks(out)
	if len(blocks) != len(keys) {
		return nil, fmt.Errorf("scutil: %d 个键得到 %d 段输出", len(keys), len(blocks))
	}
	return blocks, nil
}

// splitBlocks splits the output of several shows: each is a dictionary
// that ends with a "}" in the first column, or "No such key".
func splitBlocks(out string) []string {
	var blocks []string
	var current strings.Builder
	in := false
	for _, line := range strings.Split(out, "\n") {
		switch {
		case in:
			current.WriteString(line + "\n")
			if line == "}" {
				blocks = append(blocks, current.String())
				current.Reset()
				in = false
			}
		case strings.HasPrefix(line, "<dictionary> {"):
			in = true
			current.WriteString(line + "\n")
		case strings.Contains(line, "No such key"):
			blocks = append(blocks, "")
		}
	}
	return blocks
}

// parseValue reads a scalar of scutil's dictionary output.
func parseValue(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, " : ")
		if ok && strings.TrimSpace(k) == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

var arrayItem = regexp.MustCompile(`^\s*\d+\s*:\s*(\S+)\s*$`)

// parseServers reads the ServerAddresses array of scutil's dictionary
// output.
func parseServers(out string) []netip.Addr {
	var servers []netip.Addr
	in := false
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, "ServerAddresses") && strings.Contains(line, "<array>"):
			in = true
		case in && strings.TrimSpace(line) == "}":
			return servers
		case in:
			if m := arrayItem.FindStringSubmatch(line); m != nil {
				if addr, err := netip.ParseAddr(m[1]); err == nil {
					servers = append(servers, addr)
				}
			}
		}
	}
	return servers
}

// FirstResolver returns the first nameserver of resolver #1, the resolver
// unscoped queries without a more specific domain go to.
func FirstResolver() (string, error) {
	out, err := Runner("", "--dns")
	if err != nil {
		return "", err
	}
	return parseFirstResolver(out)
}

func parseFirstResolver(out string) (string, error) {
	in := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "resolver #1":
			in = true
		case in && strings.HasPrefix(line, "resolver #"):
			return "", errors.New("resolver #1 has no nameserver")
		case in && strings.HasPrefix(line, "nameserver[0]"):
			if _, value, ok := strings.Cut(line, ":"); ok {
				return strings.TrimSpace(value), nil
			}
		}
	}
	return "", errors.New("no resolver #1")
}

// FlushCache drops the system's DNS cache.
func FlushCache() error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/bin/dscacheutil", "-flushcache").Run()
}

// Clear removes key; removing an absent key is not an error. Temporary keys
// go by themselves; this removes what an older build may have set.
func Clear(key string) error {
	if !keyPattern.MatchString(key) {
		return fmt.Errorf("sysdns: bad key %q", key)
	}
	_, err := Runner(fmt.Sprintf("remove %s\n", key))
	return err
}
