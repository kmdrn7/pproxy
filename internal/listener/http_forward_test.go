package listener_test

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/listener"
	"github.com/kmdrn7/pproxy/internal/pool"
)

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

// TestHTTPListener_UpstreamAuth_InSameFrame locks in the fix requiring
// Proxy-Authorization on the actual CONNECT/GET, not a separate "auth"
// request that would tunnel to a different target.
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
