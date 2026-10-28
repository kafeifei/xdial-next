// Package sysdns points the system resolver into TUN while connected,
// ARCHITECTURE.md 6.4: a dynamic-store resolver that matches every domain,
// first in search order. It lives in configd's dynamic store, so it never
// reaches persistent network settings and is gone after a reboot.
package sysdns

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
)

// Server is the resolver address inside TUN; queries to it enter TUN and
// are hijacked into sing-box.
const Server = "172.19.0.2"

var keyPattern = regexp.MustCompile(`^State:/Network/Service/[A-Za-z0-9.\-]+/DNS$`)

// Runner executes scutil with a script on stdin; tests replace it.
var Runner = func(script string) error {
	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = bytes.NewBufferString(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("scutil: %v: %s", err, stderr.String())
	}
	return nil
}

// Set writes the resolver key.
func Set(key string, server netip.Addr) error {
	if !keyPattern.MatchString(key) {
		return fmt.Errorf("sysdns: bad key %q", key)
	}
	return Runner(fmt.Sprintf("d.init\nd.add ServerAddresses * %s\nd.add SupplementalMatchDomains * \"\"\nd.add SearchOrder # 1\nset %s\n", server, key))
}

// Clear removes the resolver key; removing an absent key is not an error.
func Clear(key string) error {
	if !keyPattern.MatchString(key) {
		return fmt.Errorf("sysdns: bad key %q", key)
	}
	return Runner(fmt.Sprintf("remove %s\n", key))
}
