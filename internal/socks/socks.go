// Package socks implements the SOCKS5 client bits needed for transparent
// proxying: CONNECT (TCP) and UDP ASSOCIATE (RFC 1928 / RFC 1929).
package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	ver5          = 0x05
	authNone      = 0x00
	authUserPass  = 0x02
	authNoAccept  = 0xff
	cmdConnect    = 0x01
	cmdUDPAssoc   = 0x03
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
	replySuccess  = 0x00
	maxUDPPayload = 65535
)

// Client describes a SOCKS5 proxy endpoint.
type Client struct {
	Addr string // host:port
	User string
	Pass string
}

func (c *Client) dial() (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.Dial("tcp", c.Addr)
	if err != nil {
		return nil, err
	}
	if err := c.handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) handshake(conn net.Conn) error {
	methods := []byte{authNone}
	if c.User != "" || c.Pass != "" {
		methods = append(methods, authUserPass)
	}
	req := append([]byte{ver5, byte(len(methods))}, methods...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != ver5 {
		return fmt.Errorf("socks5: bad version %d", resp[0])
	}
	switch resp[1] {
	case authNone:
		return nil
	case authUserPass:
		if err := c.authUserPass(conn); err != nil {
			return err
		}
		return nil
	case authNoAccept:
		return errors.New("socks5: no acceptable auth method")
	default:
		return fmt.Errorf("socks5: unsupported auth method %d", resp[1])
	}
}

func (c *Client) authUserPass(conn net.Conn) error {
	if len(c.User) > 255 || len(c.Pass) > 255 {
		return errors.New("socks5: credentials too long")
	}
	buf := make([]byte, 0, 3+len(c.User)+len(c.Pass))
	buf = append(buf, 0x01, byte(len(c.User)))
	buf = append(buf, c.User...)
	buf = append(buf, byte(len(c.Pass)))
	buf = append(buf, c.Pass...)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("socks5: authentication failed")
	}
	return nil
}

// DialTCP opens a TCP stream to dst (host:port or ip:port) through the proxy.
func (c *Client) DialTCP(dst string) (net.Conn, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		conn.Close()
		return nil, err
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		conn.Close()
		return nil, err
	}
	req, err := buildRequest(cmdConnect, host, uint16(p))
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	if err := readReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func buildRequest(cmd byte, host string, port uint16) ([]byte, error) {
	buf := []byte{ver5, cmd, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, atypIPv4)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, atypIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("socks5: hostname too long")
		}
		buf = append(buf, atypDomain, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))
	return buf, nil
}

func readReply(conn net.Conn) error {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != ver5 {
		return fmt.Errorf("socks5: bad reply version %d", hdr[0])
	}
	if hdr[1] != replySuccess {
		return fmt.Errorf("socks5: connect failed (reply %d)", hdr[1])
	}
	var addrLen int
	switch hdr[3] {
	case atypIPv4:
		addrLen = 4
	case atypIPv6:
		addrLen = 16
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		addrLen = int(l[0])
	default:
		return fmt.Errorf("socks5: unknown address type %d", hdr[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addrLen+2)); err != nil {
		return err
	}
	return nil
}

// UDPAssoc is an established SOCKS5 UDP association.
type UDPAssoc struct {
	ctrl net.Conn
	conn *net.UDPConn
}

// AssociateUDP performs the UDP ASSOCIATE handshake and returns the
// association. The control TCP connection is kept open for its lifetime.
func (c *Client) AssociateUDP() (*UDPAssoc, error) {
	ctrl, err := c.dial()
	if err != nil {
		return nil, err
	}
	req := []byte{ver5, cmdUDPAssoc, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := ctrl.Write(req); err != nil {
		ctrl.Close()
		return nil, err
	}
	relay, err := readReplyAddr(ctrl)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	if relay.IP.IsUnspecified() {
		host, _, _ := net.SplitHostPort(c.Addr)
		if ip := net.ParseIP(host); ip != nil {
			relay.IP = ip
		}
	}
	conn, err := net.DialUDP("udp4", nil, relay)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	return &UDPAssoc{ctrl: ctrl, conn: conn}, nil
}

func readReplyAddr(conn net.Conn) (*net.UDPAddr, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != ver5 {
		return nil, fmt.Errorf("socks5: bad reply version %d", hdr[0])
	}
	if hdr[1] != replySuccess {
		return nil, fmt.Errorf("socks5: udp associate failed (reply %d)", hdr[1])
	}
	var ip net.IP
	switch hdr[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		ip = net.IP(b)
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		ip = net.IP(b)
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return nil, err
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, d); err != nil {
			return nil, err
		}
		addrs, err := net.LookupIP(string(d))
		if err != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("socks5: cannot resolve relay %q", string(d))
		}
		ip = addrs[0]
	default:
		return nil, fmt.Errorf("socks5: unknown address type %d", hdr[3])
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(conn, p); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(p)
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

// Send wraps payload in a SOCKS5 UDP request header for dst.
func (a *UDPAssoc) Send(dst *net.UDPAddr, payload []byte) error {
	ip4 := dst.IP.To4()
	if ip4 == nil {
		return errors.New("socks5: only IPv4 UDP is supported")
	}
	buf := make([]byte, 0, 10+len(payload))
	buf = append(buf, 0x00, 0x00, 0x00, atypIPv4)
	buf = append(buf, ip4...)
	buf = append(buf, byte(dst.Port>>8), byte(dst.Port))
	buf = append(buf, payload...)
	_, err := a.conn.Write(buf)
	return err
}

// Receive reads one datagram from the association, returning the original
// source address and payload.
func (a *UDPAssoc) Receive() (*net.UDPAddr, []byte, error) {
	buf := make([]byte, maxUDPPayload+512)
	n, err := a.conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	if n < 10 || buf[0] != 0x00 || buf[1] != 0x00 {
		return nil, nil, errors.New("socks5: malformed udp reply")
	}
	// Fragment support is out of scope; only standalone datagrams are handled.
	if buf[2] != 0x00 {
		return nil, nil, errors.New("socks5: fragmented udp datagram unsupported")
	}
	var src *net.UDPAddr
	switch buf[3] {
	case atypIPv4:
		if n < 10 {
			return nil, nil, errors.New("socks5: short udp reply")
		}
		ip := net.IP(buf[4:8])
		port := binary.BigEndian.Uint16(buf[8:10])
		src = &net.UDPAddr{IP: ip, Port: int(port)}
		return src, buf[10:n], nil
	case atypIPv6:
		if n < 22 {
			return nil, nil, errors.New("socks5: short udp reply")
		}
		ip := net.IP(buf[4:20])
		port := binary.BigEndian.Uint16(buf[20:22])
		src = &net.UDPAddr{IP: ip, Port: int(port)}
		return src, buf[22:n], nil
	case atypDomain:
		if n < 5 {
			return nil, nil, errors.New("socks5: short udp reply")
		}
		l := int(buf[4])
		if n < 5+l+2 {
			return nil, nil, errors.New("socks5: short udp reply")
		}
		host := string(buf[5 : 5+l])
		port := binary.BigEndian.Uint16(buf[5+l : 5+l+2])
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, nil, fmt.Errorf("socks5: cannot resolve udp source %q", host)
		}
		src = &net.UDPAddr{IP: ips[0], Port: int(port)}
		return src, buf[5+l+2 : n], nil
	}
	return nil, nil, errors.New("socks5: unknown udp reply address type")
}

// Close tears down the association.
func (a *UDPAssoc) Close() error {
	if a.conn != nil {
		a.conn.Close()
	}
	if a.ctrl != nil {
		return a.ctrl.Close()
	}
	return nil
}
