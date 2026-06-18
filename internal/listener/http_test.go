package listener_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
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

func TestHTTPListener_ForwardsPlainHTTP(t *testing.T) {
	t.Parallel()
	up := newUpstreamProxy(t)

	poolCfg := config.Health{FailThreshold: 1, SuccessThreshold: 1}
	p := pool.New([]config.Upstream{
		{Name: "u1", Type: config.ProtocolHTTP, Address: up.server.Listener.Addr().String()},
	}, poolCfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	store, err := auth.New(nil)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	proxyURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := c.Get("http://example.com/path?q=1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Echo-Method"); got != http.MethodGet {
		t.Errorf("upstream method = %q, want GET", got)
	}
	if got := resp.Header.Get("X-Echo-Path"); got != "/path" {
		t.Errorf("upstream path = %q, want /path", got)
	}
	if got := resp.Header.Get("X-Echo-Host"); got != "example.com" {
		t.Errorf("upstream Host = %q, want example.com", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "hello from upstream") {
		t.Errorf("body = %q, want upstream response", body)
	}

	// the upstream should have seen the request
	select {
	case r := <-up.seen:
		if r.URL.Path != "/path" {
			t.Errorf("upstream saw URL.Path = %q, want /path", r.URL.Path)
		}
		if r.Host != "example.com" {
			t.Errorf("upstream saw Host = %q, want example.com", r.Host)
		}
	case <-time.After(time.Second):
		t.Fatalf("upstream did not see a request")
	}
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

// authUpstream is an httptest server that demands a specific
// Proxy-Authorization header. It records the requests it received so
// tests can assert the auth was attached to the actual CONNECT (not
// a throwaway).
type authUpstream struct {
	server *httptest.Server
	user   string
	pass   string
	seen   chan *http.Request
}

func newAuthUpstream(t *testing.T, user, pass string) *authUpstream {
	t.Helper()
	up := &authUpstream{user: user, pass: pass, seen: make(chan *http.Request, 16)}
	up.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, ok := r.BasicAuth()
		pa := r.Header.Get("Proxy-Authorization")
		if !ok && pa != "" {
			// r.BasicAuth() only fires when the request is recognised as a
			// proxy request (absolute URI). If the upstream got a relative
			// URI but the Proxy-Authorization header is present, decode it
			// manually.
			gotUser, gotPass, ok = parseBasic(pa)
		}
		if !ok || gotUser != up.user || gotPass != up.pass {
			w.Header().Set("Proxy-Authenticate", `Basic realm="upstream"`)
			http.Error(w, "upstream auth required", http.StatusProxyAuthRequired)
			return
		}
		select {
		case up.seen <- r.Clone(r.Context()):
		default:
		}
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-RequestURI", r.RequestURI)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(up.server.Close)
	return up
}

func parseBasic(header string) (string, string, bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || header[:len(prefix)] != prefix {
		return "", "", false
	}
	dec, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	for i := 0; i < len(dec); i++ {
		if dec[i] == ':' {
			return string(dec[:i]), string(dec[i+1:]), true
		}
	}
	return "", "", false
}

// TestHTTPListener_UpstreamAuth_InSameFrame locks in the fix for the
// throwaway-CONNECT bug: pproxy must attach Proxy-Authorization to the
// actual CONNECT/GET, not to a separate "auth" request that tunnels
// the connection to a different target.
func TestHTTPListener_UpstreamAuth_InSameFrame(t *testing.T) {
	t.Parallel()
	up := newAuthUpstream(t, "upuser", "uppass")

	hash := hashFor(t, "s3cret")
	store, err := auth.New([]config.User{{Username: "alice", PasswordHash: hash}})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	p := pool.New([]config.Upstream{
		{
			Name:     "u1",
			Type:     config.ProtocolHTTP,
			Address:  up.server.Listener.Addr().String(),
			Username: "upuser",
			Password: "uppass",
		},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	proxyURL := &url.URL{Scheme: "http", Host: addr, User: url.UserPassword("alice", "s3cret")}
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}

	t.Run("plain HTTP forwards with upstream auth", func(t *testing.T) {
		t.Parallel()
		resp, err := c.Get("http://example.com/path")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "upstream-ok") {
			t.Errorf("body = %q, want upstream-ok", body)
		}
		select {
		case r := <-up.seen:
			if r.RequestURI != "http://example.com/path" {
				t.Errorf("upstream saw URI %q, want http://example.com/path", r.RequestURI)
			}
		case <-time.After(time.Second):
			t.Fatalf("upstream did not see the request")
		}
	})
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

func TestHTTPListener_TryNextOnFailure(t *testing.T) {
	t.Parallel()
	// Two upstreams: first points to a closed port, second is real.
	// We expect the listener to try-next and succeed.
	up := newUpstreamProxy(t)

	deadAddr := mustClosedAddr(t)

	p := pool.New([]config.Upstream{
		{Name: "dead", Type: config.ProtocolHTTP, Address: deadAddr, DialTimeout: 300 * time.Millisecond},
		{Name: "live", Type: config.ProtocolHTTP, Address: up.server.Listener.Addr().String()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	store, _ := auth.New(nil)

	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	proxyURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := c.Get("http://example.com/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// After the failure, the dead upstream should be marked unhealthy.
	if p.Healthy("dead") {
		t.Errorf("expected dead upstream to be marked unhealthy")
	}
	if !p.Healthy("live") {
		t.Errorf("expected live upstream to remain healthy")
	}
}

func TestHTTPListener_AllUnhealthyReturns502(t *testing.T) {
	t.Parallel()
	deadAddr := mustClosedAddr(t)
	p := pool.New([]config.Upstream{
		{Name: "dead1", Type: config.ProtocolHTTP, Address: deadAddr, DialTimeout: 300 * time.Millisecond},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	store, _ := auth.New(nil)

	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	resp, err := http.Get("http://" + addr + "/") // ignored: this is a plain GET, not a proxy request
	_ = resp
	_ = err

	// Use a proxy-style request to actually exercise the handler.
	proxyURL, _ := url.Parse("http://" + addr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp2, err := c.Get("http://example.com/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp2.StatusCode)
	}
}

func TestHTTPListener_RejectsRelativeURI(t *testing.T) {
	t.Parallel()
	up := newUpstreamProxy(t)
	p := pool.New([]config.Upstream{
		{Name: "u1", Type: config.ProtocolHTTP, Address: up.server.Listener.Addr().String()},
	}, config.Health{FailThreshold: 1, SuccessThreshold: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	store, _ := auth.New(nil)
	srv := listener.NewHTTP("127.0.0.1", 0, testDeps(t, p, store))
	addr := startListener(t, srv)

	// send a plain (non-proxy) request directly to the listener
	resp, err := http.Get("http://" + addr + "/foo")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

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

// TestHTTPListener_SetDeps_SwimsWithoutRestart verifies the hot-reload
// contract: SetDeps must update the pool/auth the listener uses for
// subsequent requests without taking the listening socket down. This
// is what makes `pproxy` reloads invisible to clients.
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

// guard against unused imports if a test is later removed.
var (
	_ = strconv.Itoa
	_ = context.Background
)
