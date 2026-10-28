package daemon

import (
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
)

// peerCredentials returns the uid and groups of the process at the other
// end of a Unix socket, as the kernel recorded them when it connected.
func peerCredentials(conn *net.UnixConn) (uint32, []uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, nil, err
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
		return 0, nil, err
	}
	if sysErr != nil {
		return 0, nil, sysErr
	}
	n := int(cred.NGroups)
	if n < 0 || n > len(cred.Groups) {
		n = 0
	}
	return cred.UID, append([]uint32(nil), cred.Groups[:n]...), nil
}
