package listener_test

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/pool"
)

func TestSOCKS5Listener_ForwardsConnect(t *testing.T) {
	t.Parallel()
	up := newSOCKS5Upstream(t, nil)
	p := pool.New([]config.Upstream{
		{Name: "u1", Type: config.ProtocolSOCKS5, Address: up.addr()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	store, _ := auth.New(nil)
	_, addr := newSOCKS5Listener(t, p, store)

	conn := socks5Dial(t, addr, "example.com:443", "", "")
	defer conn.Close()

	// write a payload; the upstream echoes it back.
	payload := []byte("hello\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}

	// verify the upstream saw the right target
	if got := up.lastAtyp.Load(); got != 0x03 {
		t.Errorf("upstream saw atyp %#x, want 0x03 (domain)", got)
	}
	addrPtr := up.lastAddr.Load()
	if addrPtr == nil || string(*addrPtr) != "example.com" {
		addrStr := "<nil>"
		if addrPtr != nil {
			addrStr = string(*addrPtr)
		}
		t.Errorf("upstream saw addr %q, want example.com", addrStr)
	}
	if got := up.lastPort.Load(); got != 443 {
		t.Errorf("upstream saw port %d, want 443", got)
	}
}

func TestSOCKS5Listener_TryNextOnFailure(t *testing.T) {
	t.Parallel()
	up := newSOCKS5Upstream(t, nil)
	deadAddr := mustClosedAddr(t)
	p := pool.New([]config.Upstream{
		{Name: "dead", Type: config.ProtocolSOCKS5, Address: deadAddr, DialTimeout: 300 * time.Millisecond},
		{Name: "live", Type: config.ProtocolSOCKS5, Address: up.addr()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	store, _ := auth.New(nil)
	_, addr := newSOCKS5Listener(t, p, store)

	conn := socks5Dial(t, addr, "example.com:80", "", "")
	defer conn.Close()
	// after the dial, dead should be unhealthy, live should be healthy.
	if p.Healthy("dead") {
		t.Errorf("dead upstream should be marked unhealthy")
	}
	if !p.Healthy("live") {
		t.Errorf("live upstream should remain healthy")
	}
}

func TestSOCKS5Listener_AllUnhealthyRefuses(t *testing.T) {
	t.Parallel()
	deadAddr := mustClosedAddr(t)
	p := pool.New([]config.Upstream{
		{Name: "dead", Type: config.ProtocolSOCKS5, Address: deadAddr, DialTimeout: 300 * time.Millisecond},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	store, _ := auth.New(nil)
	_, addr := newSOCKS5Listener(t, p, store)

	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	var sel [2]byte
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		t.Fatalf("read sel: %v", err)
	}
	// proceed through method selection
	_ = sel
	// send a connect request
	_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
	// we expect a non-zero REP byte (network unreachable or similar)
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if hdr[1] == 0x00 {
		t.Errorf("expected non-zero REP for all-unhealthy pool, got 0x00")
	}
}
