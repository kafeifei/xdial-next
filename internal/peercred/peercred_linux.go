package peercred

import (
	"net"
	"syscall"
)

// UID on Linux, where CI runs the daemon's tests, comes from SO_PEERCRED.
func UID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var sysErr error
	err = raw.Control(func(fd uintptr) {
		cred, sysErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if sysErr != nil {
		return 0, sysErr
	}
	return cred.Uid, nil
}
