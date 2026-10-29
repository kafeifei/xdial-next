// Package netbind binds sockets to the physical network's interface, as
// sing-box does on macOS: they then leave through it whatever routes TUN
// has added, ARCHITECTURE.md 3.4.
package netbind

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// Dialer returns a dialer bound to iface.
func Dialer(iface string, timeout time.Duration) (*net.Dialer, error) {
	if iface == "" {
		return nil, errors.New("没有物理网络的接口")
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("找不到物理网络的接口 %s", iface)
	}
	return &net.Dialer{Timeout: timeout, Control: control(ifi.Index)}, nil
}
