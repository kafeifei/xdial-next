//go:build !darwin

package netbind

import "syscall"

// control does nothing off macOS, where XDial only runs its tests.
func control(int) func(network, address string, c syscall.RawConn) error {
	return nil
}
