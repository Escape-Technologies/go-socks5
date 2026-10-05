package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/context"
)

func TestUDPFrameRoundTrip(t *testing.T) {
	dest := &AddrSpec{IP: net.IPv4(10, 0, 0, 1), Port: 161}
	data := []byte("snmp")
	raw, err := encodeUDPFrame(dest, 0, data)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	frag, got, payload, err := readUDPFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if frag != 0 {
		t.Fatalf("bad frag: %v", frag)
	}
	if !got.IP.Equal(dest.IP) || got.Port != dest.Port {
		t.Fatalf("bad dest: %v", got)
	}
	if !bytes.Equal(payload, data) {
		t.Fatalf("bad data: %v", payload)
	}
}

func TestUDPFrameRoundTrip_FQDN(t *testing.T) {
	dest := &AddrSpec{FQDN: "snmp.example", Port: 161}
	raw, err := encodeUDPFrame(dest, 1, []byte("x"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	frag, got, payload, err := readUDPFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if frag != 1 {
		t.Fatalf("bad frag: %v", frag)
	}
	if got.FQDN != dest.FQDN || got.Port != dest.Port {
		t.Fatalf("bad dest: %v", got)
	}
	if !bytes.Equal(payload, []byte("x")) {
		t.Fatalf("bad data: %v", payload)
	}
}

func TestUDPFrameRoundTrip_Empty(t *testing.T) {
	dest := &AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	raw, err := encodeUDPFrame(dest, 0, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	frag, got, payload, err := readUDPFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if frag != 0 || len(payload) != 0 {
		t.Fatalf("bad empty: frag=%v data=%v", frag, payload)
	}
	if !got.IP.Equal(dest.IP) || got.Port != dest.Port {
		t.Fatalf("bad dest: %v", got)
	}
}

func TestRequest_Associate_RuleFail(t *testing.T) {
	s := &Server{config: &Config{
		Rules:    PermitNone(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	buf := bytes.NewBuffer([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); err == nil || err.Error() != "Associate to 0.0.0.0:0 blocked by rules" {
		t.Fatalf("err: %v", err)
	}

	out := resp.buf.Bytes()
	expected := []byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestSOCKS5_Associate_Echo(t *testing.T) {
	echo := startUDPEcho(t)
	socksAddr := startSOCKS(t, nil)
	conn := associateConn(t, socksAddr)
	defer func() { _ = conn.Close() }()

	dest := udpDest(echo)
	if err := writeUDPFrame(conn, dest, []byte("ping")); err != nil {
		t.Fatalf("err: %v", err)
	}

	_, payload := readClientFrame(t, conn)
	if !bytes.Equal(payload, []byte("ping")) {
		t.Fatalf("bad echo: %v", payload)
	}
}

func TestSOCKS5_Associate_Timeout(t *testing.T) {
	silent := startUDPSilent(t)
	echo := startUDPEcho(t)

	var closes atomic.Int32
	conf := &Config{
		UDPTimeout: 200 * time.Millisecond,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialCtx(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &closeNotify{Conn: c, fn: func() { closes.Add(1) }}, nil
		},
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}
	socksAddr := startSOCKS(t, conf)
	conn := associateConn(t, socksAddr)
	defer func() { _ = conn.Close() }()

	if err := writeUDPFrame(conn, udpDest(silent), []byte("quiet")); err != nil {
		t.Fatalf("err: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for closes.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("udp session did not time out")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := writeUDPFrame(conn, udpDest(echo), []byte("ping")); err != nil {
		t.Fatalf("err: %v", err)
	}
	_, payload := readClientFrame(t, conn)
	if !bytes.Equal(payload, []byte("ping")) {
		t.Fatalf("control conn died after udp timeout: %v", payload)
	}
}

func TestSOCKS5_Associate_BadFrag(t *testing.T) {
	got := make(chan []byte, 1)
	target := startUDPRecord(t, got)
	echo := startUDPEcho(t)
	socksAddr := startSOCKS(t, nil)
	conn := associateConn(t, socksAddr)
	defer func() { _ = conn.Close() }()

	raw, err := encodeUDPFrame(udpDest(target), 1, []byte("frag"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("err: %v", err)
	}

	select {
	case data := <-got:
		t.Fatalf("fragment forwarded: %v", data)
	case <-time.After(150 * time.Millisecond):
	}

	if err := writeUDPFrame(conn, udpDest(echo), []byte("ping")); err != nil {
		t.Fatalf("err: %v", err)
	}
	_, payload := readClientFrame(t, conn)
	if !bytes.Equal(payload, []byte("ping")) {
		t.Fatalf("bad echo after frag: %v", payload)
	}
}

func TestSOCKS5_Associate_ControlClose(t *testing.T) {
	echo := startUDPEcho(t)
	var closes atomic.Int32
	conf := &Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialCtx(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &closeNotify{Conn: c, fn: func() { closes.Add(1) }}, nil
		},
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}
	socksAddr := startSOCKS(t, conf)
	conn := associateConn(t, socksAddr)

	if err := writeUDPFrame(conn, udpDest(echo), []byte("ping")); err != nil {
		t.Fatalf("err: %v", err)
	}
	_, payload := readClientFrame(t, conn)
	if !bytes.Equal(payload, []byte("ping")) {
		t.Fatalf("bad echo: %v", payload)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("err: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for closes.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("udp relay not torn down after control close")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSOCKS5_ConnectStillWorks(t *testing.T) {
	l, err := listenTCP(t)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			return
		}
		_, _ = conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	socksAddr := startSOCKS(t, nil)
	conn, err := dialCtx(context.Background(), "tcp", socksAddr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("err: %v", err)
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(conn, auth); err != nil {
		t.Fatalf("err: %v", err)
	}

	req := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(req[8:], uint16(lAddr.Port))
	if _, err := conn.Write(append(req, []byte("ping")...)); err != nil {
		t.Fatalf("err: %v", err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("err: %v", err)
	}
	if reply[1] != successReply {
		t.Fatalf("connect failed: %v", reply[1])
	}
	out := make([]byte, 4)
	if _, err := io.ReadFull(conn, out); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(out, []byte("pong")) {
		t.Fatalf("bad: %v", out)
	}
}

type closeNotify struct {
	net.Conn
	once sync.Once
	fn   func()
}

func (c *closeNotify) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.fn)
	if err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return nil
}

func dialCtx(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s %s: %w", network, addr, err)
	}
	return c, nil
}

func listenTCP(t *testing.T) (net.Listener, error) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	return ln, nil
}

func startSOCKS(t *testing.T, conf *Config) string {
	t.Helper()
	if conf == nil {
		conf = &Config{}
	}
	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	ln, err := listenTCP(t)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = serv.Serve(ln) }()
	return ln.Addr().String()
}

func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func startUDPSilent(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func startUDPRecord(t *testing.T, got chan []byte) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			select {
			case got <- cp:
			default:
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func associateConn(t *testing.T, socksAddr string) net.Conn {
	t.Helper()
	conn, err := dialCtx(context.Background(), "tcp", socksAddr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("err: %v", err)
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(conn, auth); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(auth, []byte{socks5Version, NoAuth}) {
		t.Fatalf("bad auth: %v", auth)
	}

	if _, err := conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("err: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("err: %v", err)
	}
	if reply[0] != socks5Version || reply[1] != successReply {
		t.Fatalf("associate failed: %v", reply)
	}
	return conn
}

func udpDest(addr *net.UDPAddr) *AddrSpec {
	return &AddrSpec{IP: addr.IP, Port: addr.Port}
}

func readClientFrame(t *testing.T, conn net.Conn) (*AddrSpec, []byte) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	frag, dest, data, err := readUDPFrame(conn)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if frag != 0 {
		t.Fatalf("bad frag: %v", frag)
	}
	return dest, data
}
