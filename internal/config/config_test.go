package config

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProtocolValid(t *testing.T) {
	t.Parallel()
	for _, p := range []Protocol{ProtocolHTTP, ProtocolHTTPS, ProtocolSOCKS5} {
		if !p.Valid() {
			t.Errorf("expected %q to be valid", p)
		}
	}
	for _, p := range []Protocol{"", "ftp", "SOCKS5", "socks"} {
		if p.Valid() {
			t.Errorf("expected %q to be invalid", p)
		}
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	d := Defaults()
	if d.Logging.Level == "" || d.Logging.Format == "" {
		t.Fatalf("logging defaults empty: %+v", d.Logging)
	}
	if d.Health.Interval <= 0 || d.Health.Timeout <= 0 {
		t.Fatalf("health defaults not positive: %+v", d.Health)
	}
	if d.Server.ShutdownTimeout <= 0 {
		t.Fatalf("server shutdown timeout not positive")
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	minimal := `
listen:
  - protocol: http
    port: 8080
pool:
  - name: u1
    type: http
    address: 1.2.3.4:3128
`
	if err := os.WriteFile(path, []byte(minimal), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Health.Interval == 0 {
		t.Errorf("health interval not defaulted")
	}
	if c.Logging.Level == "" {
		t.Errorf("logging level not defaulted")
	}
	if c.Listen[0].Address != "0.0.0.0" {
		t.Errorf("listener address not defaulted, got %q", c.Listen[0].Address)
	}
}

func TestLoad_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	contents := `
unknown_field: true
listen:
  - protocol: http
    port: 8080
pool:
  - name: u1
    type: http
    address: 1.2.3.4:3128
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected unknown-field error")
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	validUpstream := Upstream{Name: "u1", Type: ProtocolHTTP, Address: "1.2.3.4:3128"}
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "ok",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
			},
		},
		{
			name:    "missing listen",
			mutate:  func(c *Config) {},
			wantErr: "listen",
		},
		{
			name: "missing pool",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
			},
			wantErr: "pool",
		},
		{
			name: "invalid listen protocol",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: "ftp", Port: 8080}}
				c.Pool = []Upstream{validUpstream}
			},
			wantErr: "protocol",
		},
		{
			name: "invalid listen port",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 0}}
				c.Pool = []Upstream{validUpstream}
			},
			wantErr: "port",
		},
		{
			name: "duplicate listen",
			mutate: func(c *Config) {
				c.Listen = []Listen{
					{Protocol: ProtocolHTTP, Address: "0.0.0.0", Port: 8080},
					{Protocol: ProtocolHTTP, Address: "0.0.0.0", Port: 8080},
				}
				c.Pool = []Upstream{validUpstream}
			},
			wantErr: "duplicate listener",
		},
		{
			name: "duplicate pool name",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{
					{Name: "u1", Type: ProtocolHTTP, Address: "1.2.3.4:3128"},
					{Name: "u1", Type: ProtocolHTTP, Address: "5.6.7.8:3128"},
				}
			},
			wantErr: "duplicate name",
		},
		{
			name: "upstream without name",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{{Type: ProtocolHTTP, Address: "1.2.3.4:3128"}}
			},
			wantErr: "name is required",
		},
		{
			name: "upstream invalid type",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{{Name: "u", Type: "ftp", Address: "1.2.3.4:3128"}}
			},
			wantErr: "invalid type",
		},
		{
			name: "upstream without address",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{{Name: "u", Type: ProtocolHTTP}}
			},
			wantErr: "address is required",
		},
		{
			name: "health interval too small",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Health.Interval = 100 * time.Millisecond
			},
			wantErr: "health.interval",
		},
		{
			name: "health timeout not less than interval",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Health.Interval = 5 * time.Second
				c.Health.Timeout = 10 * time.Second
			},
			wantErr: "health.timeout",
		},
		{
			name: "auth user without username",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Auth.Users = []User{{PasswordHash: "x"}}
			},
			wantErr: "username is required",
		},
		{
			name: "auth user without hash",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Auth.Users = []User{{Username: "u"}}
			},
			wantErr: "password_hash is required",
		},
		{
			name: "auth duplicate username",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Auth.Users = []User{
					{Username: "u", PasswordHash: "x"},
					{Username: "u", PasswordHash: "x"},
				}
			},
			wantErr: "duplicate username",
		},
		{
			name: "shutdown timeout too small",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Server.ShutdownTimeout = 50 * time.Millisecond
			},
			wantErr: "shutdown_timeout",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Defaults()
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestLoad_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("listen: [unclosed"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected parse error")
	}
}

const watcherTestConfig = `
logging:
  level: info
  format: json
server:
  metrics_address: 0.0.0.0:0
  shutdown_timeout: 5s
health:
  interval: 30s
  timeout: 5s
  fail_threshold: 2
  success_threshold: 2
auth: {}
listen:
  - protocol: http
    port: 8080
pool:
  - name: u1
    type: http
    address: 1.2.3.4:3128
`

// TestWatcher_Debounces verifies that a burst of fsnotify events
// (typical of an editor's atomic save) triggers exactly one reload after
// the debounce window, instead of N reloads.
func TestWatcher_Debounces(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(watcherTestConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var (
		mu    sync.Mutex
		calls int
	)
	onChange := func(*Config) {
		mu.Lock()
		defer mu.Unlock()
		calls++
	}

	w := NewWatcher(path, slog.New(slog.NewTextHandler(io.Discard, nil)), onChange)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Run(ctx, nil) }()

	// Give the watcher a moment to install the inotify hook.
	time.Sleep(50 * time.Millisecond)

	// Simulate an atomic save: write the file, then rename a temp file over
	// it. Both events should fire and coalesce into a single reload.
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte(watcherTestConfig), 0o600); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(watcherTestConfig), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename: %v", err)
	}

	// Wait for the debounce window plus margin.
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Errorf("calls = %d, want 1 (bursts should debounce)", got)
	}

	cancel()
	<-done
}

// TestWatcher_MidWriteTolerant simulates the partial-write race that
// produces the "EOF" errors operators see when their editor swaps the
// file. After the swap completes, a subsequent reload should succeed.
func TestWatcher_MidWriteTolerant(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(watcherTestConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var (
		mu    sync.Mutex
		calls int
	)
	onChange := func(*Config) {
		mu.Lock()
		defer mu.Unlock()
		calls++
	}

	w := NewWatcher(path, slog.New(slog.NewTextHandler(io.Discard, nil)), onChange)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Run(ctx, nil) }()
	time.Sleep(50 * time.Millisecond)

	// Mid-write: open the file, truncate it, write half a config, leave it
	// in that state. The reload triggered by this event will fail, but the
	// watcher should not crash and a subsequent complete save should still
	// be picked up.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _ = f.WriteString("listen: [unclosed")
	_ = f.Close()
	time.Sleep(400 * time.Millisecond)

	// Now write a valid config; the watcher should pick this up.
	if err := os.WriteFile(path, []byte(watcherTestConfig), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	mu.Lock()
	got := calls
	mu.Unlock()
	if got < 1 {
		t.Errorf("calls = %d, want >= 1 (subsequent good write should trigger reload)", got)
	}

	cancel()
	<-done
}
