package peercred

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// xucred is struct xucred from <sys/ucred.h>.
type xucred struct {
	Version uint32
	UID     uint32
	NGroups int16
	_       int16
	Groups  [16]uint32
}

const (
	solLocal      = 0 // SOL_LOCAL
	localPeerCred = 1 // LOCAL_PEERCRED
	xucredVersion = 0 // XUCRED_VERSION
)

// UID returns the effective uid of the process at the other end.
func UID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred xucred
	var sysErr error
	err = raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(cred))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeerCred,
			uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			sysErr = errno
		}
	})
	if err != nil {
		return 0, err
	}
	if sysErr != nil {
		return 0, sysErr
	}
	if cred.Version != xucredVersion {
		return 0, fmt.Errorf("peercred: xucred version %d", cred.Version)
	}
	return cred.UID, nil
}
