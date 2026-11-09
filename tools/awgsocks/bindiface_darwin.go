package conn

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// AWG_BIND_IFACE pins the tunnel's UDP sockets to the physical interface (IP_BOUND_IF), so that the packets to the
// server never enter the TUN device that the VPN itself creates.
func init() {
	name := os.Getenv("AWG_BIND_IFACE")
	if name == "" {
		return
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return
	}
	controlFns = append(controlFns, func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			if network == "udp6" {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifi.Index)
			} else {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifi.Index)
			}
		}); err != nil {
			return err
		}
		return serr
	})
}
