// awgsocks: AmneziaWG client in userspace (netstack) exposed as a local SOCKS5 proxy (TCP CONNECT + UDP ASSOCIATE).
// Xray uses it as the "vpn-out" outbound, so routing rules, hot switching, DNS pinning and stats keep working.
// Usage: awgsocks <wg.conf> <listen host:port>
// Built inside the amneziawg-go module (cmd/awgsocks) so it uses the same device/netstack packages.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func b64hex(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != 32 {
		return "", errors.New("bad key")
	}
	return hex.EncodeToString(raw), nil
}

type conf struct {
	addrs []netip.Addr
	dns   []netip.Addr
	mtu   int
	uapi  string
}

func parseConf(path string) (*conf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c := &conf{mtu: 1280}
	var iface, peer strings.Builder
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch section {
		case "interface":
			switch k {
			case "address":
				for _, a := range strings.Split(v, ",") {
					p, err := netip.ParsePrefix(strings.TrimSpace(a))
					if err != nil {
						return nil, err
					}
					c.addrs = append(c.addrs, p.Addr())
				}
			case "dns":
				for _, a := range strings.Split(v, ",") {
					if ip, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
						c.dns = append(c.dns, ip)
					}
				}
			case "mtu":
				c.mtu, _ = strconv.Atoi(v)
			case "privatekey":
				h, err := b64hex(v)
				if err != nil {
					return nil, err
				}
				fmt.Fprintf(&iface, "private_key=%s\n", h)
			case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5":
				fmt.Fprintf(&iface, "%s=%s\n", k, v)
			}
		case "peer":
			switch k {
			case "publickey", "presharedkey":
				h, err := b64hex(v)
				if err != nil {
					return nil, err
				}
				name := map[string]string{"publickey": "public_key", "presharedkey": "preshared_key"}[k]
				fmt.Fprintf(&peer, "%s=%s\n", name, h)
			case "endpoint":
				host, port, err := net.SplitHostPort(v)
				if err != nil {
					return nil, err
				}
				ips, err := net.LookupHost(host)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("resolve %s: %v", host, err)
				}
				fmt.Fprintf(&peer, "endpoint=%s\n", net.JoinHostPort(ips[0], port))
			case "allowedips":
				for _, a := range strings.Split(v, ",") {
					fmt.Fprintf(&peer, "allowed_ip=%s\n", strings.TrimSpace(a))
				}
			case "persistentkeepalive":
				fmt.Fprintf(&peer, "persistent_keepalive_interval=%s\n", v)
			}
		}
	}
	if len(c.addrs) == 0 || iface.Len() == 0 || peer.Len() == 0 {
		return nil, errors.New("config needs Interface Address/PrivateKey and a Peer")
	}
	if len(c.dns) == 0 {
		c.dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	c.uapi = iface.String() + peer.String()
	return c, nil
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: awgsocks <wg.conf> <host:port>")
	}
	c, err := parseConf(os.Args[1])
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	tdev, tnet, err := netstack.CreateNetTUN(c.addrs, c.dns, c.mtu)
	if err != nil {
		log.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg: "))
	if err := dev.IpcSet(c.uapi); err != nil {
		log.Fatalf("ipc: %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("READY")
	for {
		cn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serve(cn, tnet, ln.Addr().(*net.TCPAddr).IP)
	}
}

func readAddr(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, errors.New("bad atyp")
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(p), nil
}

func reply(c net.Conn, code byte, addr net.Addr) {
	b := []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
	if ta, ok := addr.(*net.TCPAddr); ok && ta.IP.To4() != nil {
		copy(b[4:8], ta.IP.To4())
		binary.BigEndian.PutUint16(b[8:], uint16(ta.Port))
	} else if ua, ok := addr.(*net.UDPAddr); ok && ua.IP.To4() != nil {
		copy(b[4:8], ua.IP.To4())
		binary.BigEndian.PutUint16(b[8:], uint16(ua.Port))
	}
	c.Write(b)
}

func serve(c net.Conn, tnet *netstack.Net, bindIP net.IP) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(h[1])); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	q := make([]byte, 4)
	if _, err := io.ReadFull(c, q); err != nil {
		return
	}
	host, port, err := readAddr(c, q[3])
	if err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	switch q[1] {
	case 1:
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		r, err := tnet.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			reply(c, 5, nil)
			return
		}
		defer r.Close()
		reply(c, 0, nil)
		done := make(chan struct{}, 2)
		go func() { io.Copy(r, c); done <- struct{}{} }()
		go func() { io.Copy(c, r); done <- struct{}{} }()
		<-done
	case 3:
		udpAssociate(c, tnet, bindIP)
	default:
		reply(c, 7, nil)
	}
}

func udpAssociate(ctl net.Conn, tnet *netstack.Net, bindIP net.IP) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		reply(ctl, 1, nil)
		return
	}
	defer pc.Close()
	reply(ctl, 0, pc.LocalAddr())
	go func() { io.Copy(io.Discard, ctl); pc.Close() }() // association ends with the control connection
	var mu sync.Mutex
	outs := map[string]net.Conn{}
	var client *net.UDPAddr
	defer func() {
		mu.Lock()
		for _, o := range outs {
			o.Close()
		}
		mu.Unlock()
	}()
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if client == nil {
			client = from
		}
		if !from.IP.Equal(client.IP) || from.Port != client.Port || n < 10 || buf[2] != 0 {
			continue
		}
		rd := strings.NewReader(string(buf[4:n]))
		host, port, err := readAddr(rd, buf[3])
		if err != nil {
			continue
		}
		payload := []byte(string(buf[n-rd.Len() : n]))
		key := net.JoinHostPort(host, strconv.Itoa(int(port)))
		mu.Lock()
		o := outs[key]
		mu.Unlock()
		if o == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			o, err = tnet.DialContext(ctx, "udp", key)
			cancel()
			if err != nil {
				continue
			}
			mu.Lock()
			outs[key] = o
			mu.Unlock()
			hdr := append([]byte{0, 0, 0}, buf[3:4]...)
			go func(o net.Conn, atyp byte, addrPort []byte) {
				rb := make([]byte, 65535)
				for {
					o.SetReadDeadline(time.Now().Add(2 * time.Minute))
					m, err := o.Read(rb)
					if err != nil {
						return
					}
					pc.WriteToUDP(append(append(append([]byte{}, hdr...), addrPort...), rb[:m]...), client)
				}
			}(o, buf[3], buf[4:n-rd.Len()])
		}
		o.Write(payload)
	}
}
