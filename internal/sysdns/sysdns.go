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
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
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
	key     string
	cmd     *exec.Cmd
	mu      sync.Mutex
	stdin   io.WriteCloser
	done    chan struct{}
	changes chan struct{}
}

// Hold starts a session that adds key as a temporary value pointing at
// server for every domain, then watches what the physical DNS is read
// from, and every service's DNS, key included. The session inherits extra,
// the connection lock of 6.1, so the lock outlives the daemon until the
// key is gone.
func Hold(key string, server netip.Addr, extra ...*os.File) (*Session, error) {
	if !keyPattern.MatchString(key) {
		return nil, fmt.Errorf("sysdns: bad key %q", key)
	}
	cmd := exec.Command(scutil)
	cmd.ExtraFiles = extra
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s := &Session{key: key, cmd: cmd, stdin: stdin, done: make(chan struct{}), changes: make(chan struct{}, 1)}
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
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := io.WriteString(s.stdin, script)
	return err
}

// Republish adds the key again, for when configd lost it (a configd
// restart drops every key). The current dictionary of the session is still
// the resolver's.
func (s *Session) Republish() error {
	return s.write(fmt.Sprintf("add %s temporary\n", s.key))
}

// Changes receives a value when the key or the physical DNS may have
// changed.
func (s *Session) Changes() <-chan struct{} { return s.changes }

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Close ends the session, which removes the key, and waits for it.
func (s *Session) Close() {
	s.mu.Lock()
	_ = s.stdin.Close()
	s.mu.Unlock()
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
	}
}

// Runner executes scutil with a script on stdin and returns its output;
// tests replace it.
var Runner = func(script string, args ...string) (string, error) {
	cmd := exec.Command(scutil, args...)
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

// Physical returns the DNS servers of the primary network service, as
// configd merges them: servers set by hand in Setup: win over those from
// DHCP or router advertisements in State:.
func Physical() ([]netip.Addr, error) {
	var service string
	for _, key := range []string{primaryIPv4, primaryIPv6} {
		out, err := Runner(fmt.Sprintf("show %s\n", key))
		if err != nil {
			return nil, err
		}
		if service = parseValue(out, "PrimaryService"); service != "" {
			break
		}
	}
	if service == "" || strings.ContainsAny(service, " \n/") {
		return nil, nil
	}
	for _, prefix := range []string{"Setup:", "State:"} {
		out, err := Runner(fmt.Sprintf("show %s/Network/Service/%s/DNS\n", prefix, service))
		if err != nil {
			return nil, err
		}
		if servers := parseServers(out); len(servers) > 0 {
			return servers, nil
		}
	}
	return nil, nil
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

// Clear removes key; removing an absent key is not an error. Temporary keys
// go by themselves; this removes what an older build may have set.
func Clear(key string) error {
	if !keyPattern.MatchString(key) {
		return fmt.Errorf("sysdns: bad key %q", key)
	}
	_, err := Runner(fmt.Sprintf("remove %s\n", key))
	return err
}
