package listener_test

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/listener"
	"github.com/kmdrn7/pproxy/internal/pool"
)

func TestHTTPListener_ConnectTunnel(t *testing.T) {
	t.Parallel()
	up := newConnectUpstream(t)
	p := pool.New([]config.Upstream{
		{Name: "u1", Type: config.ProtocolHTTP, Address: up.addr()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	store, _ := auth.New(nil)
	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	// speak CONNECT manually because the standard http client uses CONNECT
	// implicitly only for HTTPS, and we want to verify the listener accepts
	// the protocol.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := make([]byte, 1024)
	n, err := conn.Read(br)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(br[:n])
	if !strings.Contains(got, "200") {
		t.Fatalf("expected 200, got %q", got)
	}
}

// connectUpstream is a minimal HTTP-proxy stand-in that responds 200 to
// CONNECT and then echoes bytes between the two peers. It is used to
// exercise the CONNECT forwarding path without needing a real TLS target.
type connectUpstream struct {
	ln   net.Listener
	echo chan []byte
}

func newConnectUpstream(t *testing.T) *connectUpstream {
	t.Helper()
	up := &connectUpstream{echo: make(chan []byte, 16)}
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

func (u *connectUpstream) addr() string { return u.ln.Addr().String() }

func (u *connectUpstream) handle(c net.Conn) {
	defer c.Close()
	br := make([]byte, 4096)
	n, err := c.Read(br)
	if err != nil {
		return
	}
	got := string(br[:n])
	if !strings.HasPrefix(got, "CONNECT ") {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	// Respond 200 Connection Established.
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	// echo any further bytes the client sends through the tunnel.
	buf := make([]byte, 1024)
	for {
		nn, err := c.Read(buf)
		if nn > 0 {
			cp := make([]byte, nn)
			copy(cp, buf[:nn])
			select {
			case u.echo <- cp:
			default:
			}
		}
		if err != nil {
			return
		}
	}
}

func TestHTTPListener_ConnectTunnel_NoUpstreams(t *testing.T) {
	t.Parallel()
	// empty pool: CONNECT should respond with a body that explains the
	// situation rather than the bare "502 Bad Gateway" curl reports.
	p := pool.New(nil, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	store, _ := auth.New(nil)
	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := make([]byte, 4096)
	n, err := conn.Read(br)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(br[:n])
	if !strings.Contains(got, "502") {
		t.Fatalf("expected 502, got %q", got)
	}
	if !strings.Contains(got, "no upstreams configured") {
		t.Errorf("expected body to mention missing upstreams, got %q", got)
	}
}

func TestHTTPListener_ConnectTunnel_AllUnhealthy(t *testing.T) {
	t.Parallel()
	deadAddr := mustClosedAddr(t)
	p := pool.New([]config.Upstream{
		{Name: "dead", Type: config.ProtocolHTTP, Address: deadAddr, DialTimeout: 300 * time.Millisecond},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.ForceHealthy("dead", false)
	store, _ := auth.New(nil)
	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := make([]byte, 4096)
	n, err := conn.Read(br)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(br[:n])
	if !strings.Contains(got, "no healthy upstream") {
		t.Errorf("expected body to mention no healthy upstream, got %q", got)
	}
}
