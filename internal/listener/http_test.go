package listener_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/listener"
	"github.com/kmdrn7/pproxy/internal/pool"
)

// fakeProber satisfies listener.Prober. The real health.Scheduler is not
// used in these tests because we drive the pool's health state directly.
type fakeProber struct{}

func (fakeProber) RequestImmediateProbe(string) {}

// testDeps builds a Dependencies struct wired to a silent logger.
func testDeps(t *testing.T, p *pool.Pool, a *auth.Store) listener.Dependencies {
	t.Helper()
	return listener.Dependencies{
		Pool:      p,
		Auth:      a,
		Scheduler: fakeProber{},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// startListener binds a listener on a random port and starts it in a
// goroutine. t.Cleanup stops the listener.
func startListener(t *testing.T, srv listener.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Server.Serve takes over the listener, but we need the port for the
	// test. Read it now and let the listener close it on shutdown.
	addr := ln.Addr().String()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		<-done
	})
	return addr
}

// hashFor is a tiny bcrypt helper to keep the test setup terse.
func hashFor(t *testing.T, plain string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

// upstreamProxy is an httptest server that emulates a forwarding HTTP
// proxy. It records the requests it receives and returns a deterministic
// response.
type upstreamProxy struct {
	server *httptest.Server
	seen   chan *http.Request
}

func newUpstreamProxy(t *testing.T) *upstreamProxy {
	t.Helper()
	up := &upstreamProxy{seen: make(chan *http.Request, 16)}
	up.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case up.seen <- r.Clone(r.Context()):
		default:
		}
		// echo the request method and target back to the client so the test
		// can assert the upstream saw the right request. We use RequestURI
		// because http.Server normalises r.URL to a relative path even when
		// the bytes were sent with an absolute URI.
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Target", r.RequestURI)
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.Header().Set("X-Echo-Host", r.Host)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from upstream"))
	}))
	t.Cleanup(up.server.Close)
	return up
}

// mustClosedAddr returns a TCP address that is guaranteed to refuse
// connections, suitable for simulating an upstream that is down.
func mustClosedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestHTTPListener_RejectsUnauthenticated(t *testing.T) {
	t.Parallel()
	up := newUpstreamProxy(t)

	hash := hashFor(t, "s3cret")
	store, err := auth.New([]config.User{{Username: "alice", PasswordHash: hash}})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	p := pool.New([]config.Upstream{
		{Name: "u1", Type: config.ProtocolHTTP, Address: up.server.Listener.Addr().String()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got == "" {
		t.Errorf("expected Proxy-Authenticate header")
	}
}

func TestHTTPListener_AcceptsValidAuth(t *testing.T) {
	t.Parallel()
	up := newUpstreamProxy(t)

	hash := hashFor(t, "s3cret")
	store, err := auth.New([]config.User{{Username: "alice", PasswordHash: hash}})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	p := pool.New([]config.Upstream{
		{Name: "u1", Type: config.ProtocolHTTP, Address: up.server.Listener.Addr().String()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	proxyURL := &url.URL{Scheme: "http", Host: addr, User: url.UserPassword("alice", "s3cret")}
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := c.Get("http://example.com/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHTTPListener_RejectsInvalidAuth(t *testing.T) {
	t.Parallel()
	up := newUpstreamProxy(t)

	hash := hashFor(t, "s3cret")
	store, err := auth.New([]config.User{{Username: "alice", PasswordHash: hash}})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	p := pool.New([]config.Upstream{
		{Name: "u1", Type: config.ProtocolHTTP, Address: up.server.Listener.Addr().String()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	proxyURL := &url.URL{Scheme: "http", Host: addr, User: url.UserPassword("alice", "wrong")}
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := c.Get("http://example.com/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

// TestHTTPListener_SetDeps_SwimsWithoutRestart verifies SetDeps updates the
// pool/auth without taking the listening socket down.
func TestHTTPListener_SetDeps_SwimsWithoutRestart(t *testing.T) {
	t.Parallel()
	up1 := newUpstreamProxy(t)
	up2 := newUpstreamProxy(t)

	p1 := pool.New([]config.Upstream{
		{Name: "first", Type: config.ProtocolHTTP, Address: up1.server.Listener.Addr().String()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p2 := pool.New([]config.Upstream{
		{Name: "second", Type: config.ProtocolHTTP, Address: up2.server.Listener.Addr().String()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	store, _ := auth.New(nil)
	deps1 := listener.Dependencies{
		Pool:      p1,
		Auth:      store,
		Scheduler: fakeProber{},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv := listener.NewHTTP("127.0.0.1", 0, deps1)
	addr := startListener(t, srv)

	// First request goes to up1.
	proxyURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := c.Get("http://example.com/a")
	if err != nil {
		t.Fatalf("Get 1: %v", err)
	}
	resp.Body.Close()
	select {
	case r := <-up1.seen:
		if r.URL.Path != "/a" {
			t.Errorf("up1 saw %q, want /a", r.URL.Path)
		}
	case <-time.After(time.Second):
		t.Fatalf("up1 did not see first request")
	}
	select {
	case <-up2.seen:
		t.Errorf("up2 saw a request before SetDeps")
	case <-time.After(50 * time.Millisecond):
	}

	// Hot reload: swap to the second pool without shutting the listener.
	deps2 := listener.Dependencies{
		Pool:      p2,
		Auth:      store,
		Scheduler: fakeProber{},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv.SetDeps(deps2)

	resp, err = c.Get("http://example.com/b")
	if err != nil {
		t.Fatalf("Get 2: %v", err)
	}
	resp.Body.Close()
	select {
	case r := <-up2.seen:
		if r.URL.Path != "/b" {
			t.Errorf("up2 saw %q, want /b", r.URL.Path)
		}
	case <-time.After(time.Second):
		t.Fatalf("up2 did not see second request after SetDeps")
	}
	select {
	case <-up1.seen:
		t.Errorf("up1 saw a request after SetDeps")
	case <-time.After(50 * time.Millisecond):
	}
}
