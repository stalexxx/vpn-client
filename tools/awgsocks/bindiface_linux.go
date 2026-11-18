package conn

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// AWG_BIND_IFACE pins the tunnel's UDP sockets to the physical interface (SO_BINDTODEVICE), so that the packets to the
// server never enter the TUN device that the VPN itself creates. Needs CAP_NET_RAW (the helper runs as root).
func init() {
	name := os.Getenv("AWG_BIND_IFACE")
	if name == "" {
		return
	}
	controlFns = append(controlFns, func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
		}); err != nil {
			return err
		}
		return serr
	})
}
