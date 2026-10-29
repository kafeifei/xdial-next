//go:build !darwin

package resource

import "syscall"

// bindControl does nothing off macOS, where XDial only runs its tests.
func bindControl(int) func(network, address string, c syscall.RawConn) error {
	return nil
}
