package netbind

import "syscall"

// control binds a socket to one interface.
func control(index int) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		var err error
		ctlErr := c.Control(func(fd uintptr) {
			switch network {
			case "tcp6", "udp6":
				err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, index)
			default:
				err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, index)
			}
		})
		if ctlErr != nil {
			return ctlErr
		}
		return err
	}
}
