// Package socks5 implements a SOCKS5 server.
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/context"
)

const (
	defaultUDPTimeout = 30 * time.Second
	maxUDPDatagram    = 65535
	udpRSVSize        = 2
	udpFragSize       = 1
	udpHeaderPrefix   = udpRSVSize + udpFragSize
	maxFQDNLen        = 255
)

var (
	errUDPFrameTooLarge = errors.New("UDP frame too large")
	errFQDNTooLong      = errors.New("FQDN too long")
)

// Framed datagram on the ASSOCIATE TCP control connection (not a spec UDP relay):
//
//	+-----+------+------+----------+----------+----------+
//	| RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+-----+------+------+----------+----------+----------+
//	|  2  |  1   |  1   | Variable |    2     | Variable |
//	+-----+------+------+----------+----------+----------+
//
// RSV is the big-endian length of DATA (TCP stream framing). FRAG must be 0.

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.w.Write(p)
	if err != nil {
		return n, fmt.Errorf("write associate frame: %w", err)
	}
	return n, nil
}

type udpSession struct {
	conn  net.Conn
	reply *AddrSpec
}

type associateRelay struct {
	s        *Server
	writer   io.Writer
	timeout  time.Duration
	mu       sync.Mutex
	sessions map[string]*udpSession
}

func (s *Server) relayAssociate(ctx context.Context, conn conn, req *Request) error {
	timeout := s.config.UDPTimeout
	if timeout == 0 {
		timeout = defaultUDPTimeout
	}
	r := &associateRelay{
		s:        s,
		writer:   &lockedWriter{w: conn},
		timeout:  timeout,
		sessions: make(map[string]*udpSession),
	}
	defer r.closeAll()

	for {
		frag, dest, data, err := readUDPFrame(req.bufConn)
		if err != nil {
			if isAssociateEOF(err) {
				return nil
			}
			return err
		}
		if frag != 0 {
			s.config.Logger.Printf("[ERR] socks: dropping fragmented UDP datagram")
			continue
		}
		reply := *dest
		if dest.FQDN != "" && len(dest.IP) == 0 {
			_, ip, resErr := s.config.Resolver.Resolve(ctx, dest.FQDN)
			if resErr != nil {
				s.config.Logger.Printf("[ERR] socks: resolve %s: %v", dest.FQDN, resErr)
				continue
			}
			dest.IP = ip
		}
		sess, err := r.getOrDial(ctx, dest, &reply)
		if err != nil {
			s.config.Logger.Printf("[ERR] socks: udp dial %v: %v", dest, err)
			continue
		}
		if _, err := sess.conn.Write(data); err != nil {
			s.config.Logger.Printf("[ERR] socks: udp write %v: %v", dest, err)
			r.drop(dest.Address())
			continue
		}
	}
}

func isAssociateEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}

func (r *associateRelay) getOrDial(ctx context.Context, dest, reply *AddrSpec) (*udpSession, error) {
	key := dest.Address()
	r.mu.Lock()
	if sess, ok := r.sessions[key]; ok {
		r.mu.Unlock()
		return sess, nil
	}
	r.mu.Unlock()

	c, err := r.dialUDP(ctx, key)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	if sess, ok := r.sessions[key]; ok {
		r.mu.Unlock()
		_ = c.Close()
		return sess, nil
	}
	replyCopy := *reply
	sess := &udpSession{conn: c, reply: &replyCopy}
	r.sessions[key] = sess
	r.mu.Unlock()

	go r.readLoop(key, sess)
	return sess, nil
}

func (r *associateRelay) dialUDP(ctx context.Context, addr string) (net.Conn, error) {
	dial := r.s.config.Dial
	if dial == nil {
		var d net.Dialer
		c, err := d.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, fmt.Errorf("dial udp %s: %w", addr, err)
		}
		return c, nil
	}
	c, err := dial(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial udp %s: %w", addr, err)
	}
	return c, nil
}

func (r *associateRelay) readLoop(key string, sess *udpSession) {
	defer r.drop(key)

	buf := make([]byte, maxUDPDatagram)
	for {
		if err := sess.conn.SetReadDeadline(time.Now().Add(r.timeout)); err != nil {
			return
		}
		n, err := sess.conn.Read(buf)
		if err != nil {
			return
		}
		if err := writeUDPFrame(r.writer, sess.reply, buf[:n]); err != nil {
			return
		}
	}
}

func (r *associateRelay) drop(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sess, ok := r.sessions[key]; ok {
		_ = sess.conn.Close()
		delete(r.sessions, key)
	}
}

func (r *associateRelay) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, sess := range r.sessions {
		_ = sess.conn.Close()
		delete(r.sessions, key)
	}
}

func readUDPFrame(r io.Reader) (uint8, *AddrSpec, []byte, error) {
	hdr := make([]byte, udpHeaderPrefix)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, nil, fmt.Errorf("read udp frame header: %w", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[:udpRSVSize]))
	frag := hdr[udpRSVSize]
	dest, err := readAddrSpec(r)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read udp frame dest: %w", err)
	}
	if n == 0 {
		return frag, dest, nil, nil
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return 0, nil, nil, fmt.Errorf("read udp frame data: %w", err)
	}
	return frag, dest, data, nil
}

func writeUDPFrame(w io.Writer, addr *AddrSpec, data []byte) error {
	frame, err := encodeUDPFrame(addr, 0, data)
	if err != nil {
		return err
	}
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("write udp frame: %w", err)
	}
	return nil
}

func encodeUDPFrame(addr *AddrSpec, frag uint8, data []byte) ([]byte, error) {
	if len(data) > maxUDPDatagram {
		return nil, errUDPFrameTooLarge
	}
	out := make([]byte, 0, udpHeaderPrefix+len(data))
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	out = append(out, frag)
	var err error
	out, err = appendAddrSpec(out, addr)
	if err != nil {
		return nil, err
	}
	return append(out, data...), nil
}

func appendAddrSpec(b []byte, addr *AddrSpec) ([]byte, error) {
	switch {
	case addr.FQDN != "":
		if len(addr.FQDN) > maxFQDNLen {
			return nil, errFQDNTooLong
		}
		b = append(b, fqdnAddress, byte(len(addr.FQDN)))
		b = append(b, addr.FQDN...)
	case addr.IP.To4() != nil:
		b = append(b, ipv4Address)
		b = append(b, addr.IP.To4()...)
	case addr.IP.To16() != nil:
		b = append(b, ipv6Address)
		b = append(b, addr.IP.To16()...)
	default:
		return nil, fmt.Errorf("failed to format address: %v", addr)
	}
	return binary.BigEndian.AppendUint16(b, uint16(addr.Port)), nil
}
