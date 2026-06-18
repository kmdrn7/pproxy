package health

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/pool"
)

func TestHostOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"http://example.com/", "example.com"},
		{"http://example.com/foo", "example.com"},
		{"http://example.com:8080/foo?bar=1", "example.com:8080"},
		{"https://example.com#anchor", "example.com"},
		{"example.com", "example.com"},
		{"", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := hostOnly(tc.in); got != tc.want {
				t.Fatalf("hostOnly(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNewWithTargets_FallsBackToDefaults(t *testing.T) {
	t.Parallel()
	s := NewWithTargets(nil, config.Health{}, ProbeTargets{}, silentLogger())
	if s.targets.url != defaultProbeURL {
		t.Errorf("url = %q, want %q", s.targets.url, defaultProbeURL)
	}
	if s.targets.host != defaultProbeHost {
		t.Errorf("host = %q, want %q", s.targets.host, defaultProbeHost)
	}
}

func TestNewWithTargets_HonoursOverride(t *testing.T) {
	t.Parallel()
	s := NewWithTargets(nil, config.Health{}, ProbeTargets{
		URL:  "http://probe.internal/",
		Host: "probe.internal:8080",
	}, silentLogger())
	if s.targets.url != "http://probe.internal/" {
		t.Errorf("url = %q, want %q", s.targets.url, "http://probe.internal/")
	}
	if s.targets.host != "probe.internal:8080" {
		t.Errorf("host = %q, want %q", s.targets.host, "probe.internal:8080")
	}
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestProbeHTTP_DefaultTargetIsExampleDotCom(t *testing.T) {
	// sanity check that the default probe URL is something proxies commonly
	// accept (port 80, well-known domain). This guards against accidental
	// regressions to the previous "1.1.1.1:443" target that strict
	// proxies reject with 400.
	t.Parallel()
	if !strings.HasPrefix(defaultProbeURL, "http://") {
		t.Fatalf("defaultProbeURL should use http://, got %q", defaultProbeURL)
	}
	if strings.Contains(defaultProbeURL, ":443") {
		t.Fatalf("defaultProbeURL should not pin port 443 (port-mismatch with http:// causes 400s): %q", defaultProbeURL)
	}
	if !strings.Contains(defaultProbeURL, "example.com") {
		t.Logf("defaultProbeURL no longer uses example.com: %q (informational)", defaultProbeURL)
	}
}

func TestParsePort(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"80", 80, false},
		{"1", 1, false},
		{"65535", 65535, false},
		{"0", 0, true},
		{"65536", 0, true},
		{"abc", 0, true},
		{"", 0, true},
		{"-1", 0, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := parsePort(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestHostnameOf(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"1.2.3.4:80", "1.2.3.4"},
		{"[::1]:1080", "::1"},
		{"example.com:443", "example.com"},
		{"no-port", "no-port"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := hostnameOf(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBasicAuthHeader(t *testing.T) {
	t.Parallel()
	got := basicAuthHeader("alice", "s3cret")
	want := "YWxpY2U6czNjcmV0"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLoadCAPool(t *testing.T) {
	t.Parallel()
	t.Run("empty path returns nil pool", func(t *testing.T) {
		t.Parallel()
		p, err := loadCAPool("")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if p != nil {
			t.Fatalf("expected nil, got %+v", p)
		}
	})
	t.Run("missing file errors", func(t *testing.T) {
		t.Parallel()
		if _, err := loadCAPool("/nonexistent/ca.pem"); err == nil {
			t.Fatalf("expected error for missing file")
		}
	})
	t.Run("garbage pem errors", func(t *testing.T) {
		t.Parallel()
		if _, err := loadCAPool("/dev/null"); err == nil {
			t.Fatalf("expected error for empty pem")
		}
	})
}

func TestAssertStatus2xx(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"200", "HTTP/1.1 200 OK\r\n", false},
		{"204", "HTTP/1.1 204 No Content\r\n", false},
		{"302 redirect", "HTTP/1.1 302 Found\r\n", true},
		{"500", "HTTP/1.1 500 Internal Server Error\r\n", true},
		{"truncated", "HTTP/1.1 2", false},
		{"garbage", "totally not http", true},
		{"empty", "", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := assertStatus2xx([]byte(tc.in))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestFirstLine(t *testing.T) {
	t.Parallel()
	if got := firstLine([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")); got != "HTTP/1.1 200 OK\r" {
		t.Fatalf("got %q", got)
	}
	if got := firstLine([]byte("only one line")); got != "only one line" {
		t.Fatalf("got %q", got)
	}
}

// TestProbeHTTP exercises the HTTP probe against a real httptest server
// speaking the upstream HTTP-proxy protocol. The server's role is to act
// as the "remote proxy" that pproxy probes.
func newTestScheduler(t *testing.T) *Scheduler {
	t.Helper()
	return New(pool.New(nil, config.Health{FailThreshold: 1, SuccessThreshold: 1}, nil), config.Health{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestProbeHTTP(t *testing.T) {
	t.Parallel()
	s := newTestScheduler(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Minimal HTTP proxy: respond 200 to any GET. The probe only checks
		// for a 2xx status line.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	// httptest.Server.URL looks like http://127.0.0.1:NNNN. Strip the
	// scheme to get the address the dialer expects.
	addr := upstream.Listener.Addr().String()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := s.probeHTTP(ctx, config.Upstream{Address: addr})
		if err != nil {
			t.Fatalf("probeHTTP: %v", err)
		}
	})

	t.Run("non-2xx response", func(t *testing.T) {
		t.Parallel()
		failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(failing.Close)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := s.probeHTTP(ctx, config.Upstream{Address: failing.Listener.Addr().String()})
		if err == nil {
			t.Fatalf("expected error on 500 response")
		}
	})

	t.Run("unreachable upstream", func(t *testing.T) {
		t.Parallel()
		// bind a listener but close it to get a guaranteed-unreachable port
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.probeHTTP(ctx, config.Upstream{Address: addr, DialTimeout: 500 * time.Millisecond}); err == nil {
			t.Fatalf("expected error for unreachable upstream")
		}
	})
}

func TestProbeSOCKS5_Rejects(t *testing.T) {
	t.Parallel()
	s := newTestScheduler(t)
	t.Run("unreachable upstream", func(t *testing.T) {
		t.Parallel()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.probeSOCKS5(ctx, config.Upstream{Address: addr, DialTimeout: 500 * time.Millisecond}); err == nil {
			t.Fatalf("expected error for unreachable upstream")
		}
	})
}

func TestProbe_Dispatch(t *testing.T) {
	t.Parallel()
	s := &Scheduler{
		pool:     pool.New(nil, config.Health{FailThreshold: 1, SuccessThreshold: 1}, nil),
		requests: make(chan string, 1),
	}
	// unsupported protocol should error.
	if err := s.probe(context.Background(), config.Upstream{Type: "ftp"}); err == nil {
		t.Fatalf("expected error for unsupported protocol")
	}
}

func TestScheduler_RequestImmediateProbe_NonBlocking(t *testing.T) {
	t.Parallel()
	s := &Scheduler{requests: make(chan string, 3)}
	s.RequestImmediateProbe("a")
	s.RequestImmediateProbe("b")
	s.RequestImmediateProbe("c")
	// All three calls return without blocking. Drain the channel and
	// check the values.
	got := []string{<-s.requests, <-s.requests, <-s.requests}
	want := []string{"a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestScheduler_RequestImmediateProbe_DropsWhenFull(t *testing.T) {
	t.Parallel()
	s := &Scheduler{requests: make(chan string, 1)}
	s.RequestImmediateProbe("a")
	s.RequestImmediateProbe("b") // dropped: buffer full
	s.RequestImmediateProbe("c") // dropped: buffer full
	if got := <-s.requests; got != "a" {
		t.Fatalf("only a should be buffered, got %q", got)
	}
}

func TestScheduler_ProbeOne_UnknownName(t *testing.T) {
	t.Parallel()
	s := &Scheduler{
		pool:     pool.New(nil, config.Health{FailThreshold: 1, SuccessThreshold: 1}, nil),
		health:   config.Health{},
		requests: make(chan string, 1),
	}
	// unknown name is a no-op, not a panic.
	s.probeOne(context.Background(), "nope")
}

var _ = errors.New
