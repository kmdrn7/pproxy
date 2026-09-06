package config

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

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
