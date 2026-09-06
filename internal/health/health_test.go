package health

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/pool"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestScheduler builds a Scheduler suitable for exercising probeHTTP and
// probeSOCKS5 directly in tests.
func newTestScheduler(t *testing.T) *Scheduler {
	t.Helper()
	return New(pool.New(nil, config.Health{FailThreshold: 1, SuccessThreshold: 1}, nil), config.Health{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
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

func TestScheduler_Stop_ExitsRun(t *testing.T) {
	t.Parallel()
	s := &Scheduler{
		pool:     pool.New(nil, config.Health{FailThreshold: 1, SuccessThreshold: 1}, nil),
		health:   config.Health{Interval: time.Hour, Timeout: time.Second},
		requests: make(chan string, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()

	// Stop must unblock Run and return promptly even though the ticker
	// interval is an hour.
	stopDone := make(chan struct{})
	go func() { s.Stop(); close(stopDone) }()

	select {
	case <-stopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s")
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s after Stop")
	}

	// Calling Stop again must be a no-op (no panic, no hang).
	s.Stop()
}

// TestScheduler_RebuildAfterStop is the regression test for the reload bug
// where the listener's Prober shim stayed wired to a scheduler that was
// never rebuilt, so new upstreams went unprobed after a reload.
func TestScheduler_RebuildAfterStop(t *testing.T) {
	t.Parallel()

	// Upstream A: the old pool. Stop returns when the scheduler goroutine
	// sees the stop signal.
	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstreamA.Close)

	// Upstream B: appears only after the reload. The new scheduler must
	// probe it; if the Prober shim were still pointing at the old
	// scheduler, B would never be touched.
	probeHits := make(chan string, 8)
	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probeHits <- "B"
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstreamB.Close)

	poolA := pool.New(
		[]config.Upstream{{Name: "A", Type: config.ProtocolHTTP, Address: upstreamA.Listener.Addr().String()}},
		config.Health{FailThreshold: 1, SuccessThreshold: 1, Timeout: time.Second},
		silentLogger(),
	)
	poolB := pool.New(
		[]config.Upstream{{Name: "B", Type: config.ProtocolHTTP, Address: upstreamB.Listener.Addr().String()}},
		config.Health{FailThreshold: 1, SuccessThreshold: 1, Timeout: time.Second},
		silentLogger(),
	)

	// First scheduler probes pool A.
	first := New(poolA, config.Health{
		Interval:         time.Hour, // don't tick during the test
		Timeout:          time.Second,
		FailThreshold:    1,
		SuccessThreshold: 1,
	}, silentLogger())
	runDone := make(chan error, 1)
	go func() { runDone <- first.Run(context.Background()) }()
	first.RequestImmediateProbe("A")

	// Simulate a reload: stop the first scheduler, build a second one
	// against pool B. main.go does this swap atomically; the test just
	// confirms the pieces fit together.
	first.Stop()

	second := New(poolB, config.Health{
		Interval:         time.Hour,
		Timeout:          time.Second,
		FailThreshold:    1,
		SuccessThreshold: 1,
	}, silentLogger())
	go func() { _ = second.Run(context.Background()) }()
	t.Cleanup(second.Stop)

	second.RequestImmediateProbe("B")

	select {
	case got := <-probeHits:
		if got != "B" {
			t.Fatalf("probe hit = %q, want B", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("B was not probed within 2s — the reload swap did not work")
	}

	if !poolB.Healthy("B") {
		t.Fatal("pool B should be healthy after a successful probe")
	}
}
