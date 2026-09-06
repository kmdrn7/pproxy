package listener_test

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/listener"
	"github.com/kmdrn7/pproxy/internal/pool"
)

// socks5Upstream is a tiny in-process SOCKS5 server used to exercise the
// SOCKS5 listener end-to-end. It supports:
//   - no-auth method
//   - username/password (when creds is set)
//   - connect command
//
// It also records the most recent connect target so tests can assert.
type socks5Upstream struct {
	ln       net.Listener
	creds    *socks5Creds // nil = no auth
	lastAtyp atomic.Int32
	lastAddr atomic.Pointer[[]byte]
	lastPort atomic.Uint32
}

type socks5Creds struct {
	user, pass string
}

func newSOCKS5Upstream(t *testing.T, creds *socks5Creds) *socks5Upstream {
	t.Helper()
	up := &socks5Upstream{creds: creds}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	up.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go up.handle(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return up
}

func (u *socks5Upstream) addr() string { return u.ln.Addr().String() }

func (u *socks5Upstream) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	// method negotiation
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	chosen := byte(0xFF)
	if u.creds != nil {
		for _, m := range methods {
			if m == 0x02 {
				chosen = 0x02
				break
			}
		}
	} else {
		for _, m := range methods {
			if m == 0x00 {
				chosen = 0x00
				break
			}
		}
	}
	if _, err := c.Write([]byte{0x05, chosen}); err != nil {
		return
	}
	if chosen == 0xFF {
		return
	}
	if chosen == 0x02 {
		if !u.doAuth(c) {
			return
		}
	}
	// connect request
	var reqHdr [4]byte
	if _, err := io.ReadFull(c, reqHdr[:]); err != nil {
		return
	}
	if reqHdr[0] != 0x05 || reqHdr[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	u.lastAtyp.Store(int32(reqHdr[3]))
	var addr []byte
	switch reqHdr[3] {
	case 0x01:
		addr = make([]byte, 4)
	case 0x04:
		addr = make([]byte, 16)
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		addr = make([]byte, l[0])
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := io.ReadFull(c, addr); err != nil {
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return
	}
	u.lastAddr.Store(&addr)
	u.lastPort.Store(uint32(binary.BigEndian.Uint16(port[:])))

	// reply success with zero bind address
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	if _, err := c.Write(reply); err != nil {
		return
	}
	// echo bytes back so the test can detect liveness.
	_, _ = io.Copy(c, c)
}

func (u *socks5Upstream) doAuth(c net.Conn) bool {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return false
	}
	if hdr[0] != 0x01 {
		return false
	}
	user := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return false
	}
	var pl [1]byte
	if _, err := io.ReadFull(c, pl[:]); err != nil {
		return false
	}
	pass := make([]byte, pl[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return false
	}
	if string(user) == u.creds.user && string(pass) == u.creds.pass {
		_, _ = c.Write([]byte{0x01, 0x00})
		return true
	}
	_, _ = c.Write([]byte{0x01, 0x01})
	return false
}

// socks5Dial sends a SOCKS5 connect through addr to target and returns the
// established connection. The caller is responsible for closing it.
func socks5Dial(t *testing.T, addr, target string, user, pass string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	methods := []byte{0x00, 0x02}
	if user != "" {
		methods = []byte{0x02}
	}
	if _, err := c.Write([]byte{0x05, byte(len(methods))}); err != nil {
		t.Fatalf("write nmethods: %v", err)
	}
	if _, err := c.Write(methods); err != nil {
		t.Fatalf("write methods: %v", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		t.Fatalf("read selection: %v", err)
	}
	if sel[0] != 0x05 {
		t.Fatalf("bad version in selection: %#x", sel[0])
	}
	if sel[1] == 0xFF {
		t.Fatalf("server rejected all methods")
	}
	if sel[1] == 0x02 {
		// send user/pass
		frame := []byte{0x01, byte(len(user))}
		frame = append(frame, user...)
		frame = append(frame, byte(len(pass)))
		frame = append(frame, pass...)
		if _, err := c.Write(frame); err != nil {
			t.Fatalf("write creds: %v", err)
		}
		var resp [2]byte
		if _, err := io.ReadFull(c, resp[:]); err != nil {
			t.Fatalf("read auth resp: %v", err)
		}
		if resp[1] != 0x00 {
			t.Fatalf("auth failed: %#x", resp[1])
		}
	}
	// connect request
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split target: %v", err)
	}
	pn, _ := net.LookupPort("tcp", port)
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	pb := [2]byte{byte(pn >> 8), byte(pn & 0xff)}
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	replyHdr := make([]byte, 4)
	if _, err := io.ReadFull(c, replyHdr); err != nil {
		t.Fatalf("read reply hdr: %v", err)
	}
	if replyHdr[1] != 0x00 {
		t.Fatalf("connect refused: %#x", replyHdr[1])
	}
	var addrLen int
	switch replyHdr[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			t.Fatalf("read atyp len: %v", err)
		}
		addrLen = int(l[0])
	default:
		t.Fatalf("bad atyp: %#x", replyHdr[3])
	}
	if addrLen > 0 {
		if _, err := io.ReadFull(c, make([]byte, addrLen)); err != nil {
			t.Fatalf("read bind addr: %v", err)
		}
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil { // port
		t.Fatalf("read bind port: %v", err)
	}
	// clear deadline so caller can use the conn
	_ = c.SetDeadline(time.Time{})
	return c
}

func newSOCKS5Listener(t *testing.T, p *pool.Pool, store *auth.Store) (listener.Server, string) {
	t.Helper()
	srv := listener.NewSOCKS5("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)
	return srv, addr
}

func TestSOCKS5Listener_RejectsWithoutAuth(t *testing.T) {
	t.Parallel()
	up := newSOCKS5Upstream(t, nil)

	hash := hashFor(t, "s3cret")
	store, err := auth.New([]config.User{{Username: "alice", PasswordHash: hash}})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	p := pool.New([]config.Upstream{
		{Name: "u1", Type: config.ProtocolSOCKS5, Address: up.addr()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, addr := newSOCKS5Listener(t, p, store)

	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// offer only no-auth
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	var sel [2]byte
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		t.Fatalf("read: %v", err)
	}
	if sel[1] != 0xFF {
		t.Errorf("server should reject with 0xFF when auth required, got %#x", sel[1])
	}
}

func TestSOCKS5Listener_AcceptsValidAuth(t *testing.T) {
	t.Parallel()
	up := newSOCKS5Upstream(t, nil)
	hash := hashFor(t, "s3cret")
	store, _ := auth.New([]config.User{{Username: "alice", PasswordHash: hash}})
	p := pool.New([]config.Upstream{
		{Name: "u1", Type: config.ProtocolSOCKS5, Address: up.addr()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, addr := newSOCKS5Listener(t, p, store)

	conn := socks5Dial(t, addr, "1.2.3.4:80", "alice", "s3cret")
	defer conn.Close()
	// quick smoke: send a byte, expect it echoed
	_, _ = conn.Write([]byte{0x42})
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if buf[0] != 0x42 {
		t.Errorf("got %#x, want 0x42", buf[0])
	}
}

func TestSOCKS5Listener_RejectsInvalidAuth(t *testing.T) {
	t.Parallel()
	up := newSOCKS5Upstream(t, nil)
	hash := hashFor(t, "s3cret")
	store, _ := auth.New([]config.User{{Username: "alice", PasswordHash: hash}})
	p := pool.New([]config.Upstream{
		{Name: "u1", Type: config.ProtocolSOCKS5, Address: up.addr()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, addr := newSOCKS5Listener(t, p, store)

	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{0x05, 0x01, 0x02})
	var sel [2]byte
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		t.Fatalf("read sel: %v", err)
	}
	if sel[1] != 0x02 {
		t.Fatalf("server should pick 0x02 auth, got %#x", sel[1])
	}
	frame := []byte{0x01, byte(len("alice"))}
	frame = append(frame, "alice"...)
	frame = append(frame, byte(len("wrong")))
	frame = append(frame, "wrong"...)
	_, _ = c.Write(frame)
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if resp[1] != 0x01 {
		t.Errorf("auth should fail, got %#x", resp[1])
	}
}
