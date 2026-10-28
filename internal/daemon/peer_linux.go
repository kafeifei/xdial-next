package daemon

import (
	"net"
	"syscall"
)

// peerCredentials on Linux, where CI runs the daemon's tests, reports the
// peer's uid and primary group from SO_PEERCRED.
func peerCredentials(conn *net.UnixConn) (uint32, []uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, nil, err
	}
	var cred *syscall.Ucred
	var sysErr error
	err = raw.Control(func(fd uintptr) {
		cred, sysErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, nil, err
	}
	if sysErr != nil {
		return 0, nil, sysErr
	}
	return cred.Uid, []uint32{cred.Gid}, nil
}
