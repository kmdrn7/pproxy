package pool

import (
	"io"
	"log/slog"
	"testing"

	"github.com/kmdrn7/pproxy/internal/config"
)

// silentLogger discards all log output so test runs stay quiet.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newPool(t *testing.T, health config.Health, ups ...config.Upstream) *Pool {
	t.Helper()
	return New(ups, health, silentLogger())
}

func TestPool_Next_Empty(t *testing.T) {
	t.Parallel()
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1})
	if u, ok := p.Next(config.ProtocolHTTP); ok || u != nil {
		t.Fatalf("expected no upstream, got %+v ok=%v", u, ok)
	}
}

func TestPool_Next_RoundRobin(t *testing.T) {
	t.Parallel()
	ups := []config.Upstream{
		{Name: "a", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"},
		{Name: "b", Type: config.ProtocolHTTP, Address: "2.2.2.2:80"},
		{Name: "c", Type: config.ProtocolHTTP, Address: "3.3.3.3:80"},
	}
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1}, ups...)

	got := make([]string, 0, 6)
	for i := 0; i < 6; i++ {
		u, ok := p.Next(config.ProtocolHTTP)
		if !ok {
			t.Fatalf("iter %d: no upstream", i)
		}
		got = append(got, u.Name)
	}
	// should visit each in order, then wrap.
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("iter %d: got %q, want %q (full: %v)", i, got[i], w, got)
		}
	}
}

func TestPool_Next_ProtocolFilter(t *testing.T) {
	t.Parallel()
	ups := []config.Upstream{
		{Name: "h", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"},
		{Name: "s", Type: config.ProtocolSOCKS5, Address: "1.1.1.1:1080"},
	}
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1}, ups...)

	for i := 0; i < 4; i++ {
		u, ok := p.Next(config.ProtocolHTTP)
		if !ok {
			t.Fatalf("iter %d: expected HTTP upstream", i)
		}
		if u.Type != config.ProtocolHTTP {
			t.Errorf("iter %d: got type %q, want http", i, u.Type)
		}
	}
	for i := 0; i < 4; i++ {
		u, ok := p.Next(config.ProtocolSOCKS5)
		if !ok {
			t.Fatalf("iter %d: expected SOCKS5 upstream", i)
		}
		if u.Type != config.ProtocolSOCKS5 {
			t.Errorf("iter %d: got type %q, want socks5", i, u.Type)
		}
	}
}

func TestPool_Next_SkipsUnhealthy(t *testing.T) {
	t.Parallel()
	ups := []config.Upstream{
		{Name: "a", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"},
		{Name: "b", Type: config.ProtocolHTTP, Address: "2.2.2.2:80"},
	}
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1}, ups...)

	p.RecordDown("a")
	p.RecordDown("a")
	p.RecordDown("a") // extra; should not matter once threshold is met

	for i := 0; i < 4; i++ {
		u, ok := p.Next(config.ProtocolHTTP)
		if !ok {
			t.Fatalf("iter %d: expected upstream", i)
		}
		if u.Name != "b" {
			t.Errorf("iter %d: got %q, want b (a should be skipped)", i, u.Name)
		}
	}
}

func TestPool_Next_AllUnhealthy(t *testing.T) {
	t.Parallel()
	ups := []config.Upstream{
		{Name: "a", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"},
		{Name: "b", Type: config.ProtocolHTTP, Address: "2.2.2.2:80"},
	}
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1}, ups...)
	p.RecordDown("a")
	p.RecordDown("b")

	if u, ok := p.Next(config.ProtocolHTTP); ok || u != nil {
		t.Fatalf("expected no upstream, got %+v ok=%v", u, ok)
	}
}

func TestPool_RecordUp_ReachesHealthy(t *testing.T) {
	t.Parallel()
	ups := []config.Upstream{{Name: "a", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"}}
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 3}, ups...)

	p.RecordDown("a")
	p.RecordDown("a")
	if p.Healthy("a") {
		t.Fatalf("expected unhealthy after RecordDown")
	}
	// success threshold is 3
	p.RecordUp("a")
	if p.Healthy("a") {
		t.Fatalf("expected still unhealthy after 1 success")
	}
	p.RecordUp("a")
	if p.Healthy("a") {
		t.Fatalf("expected still unhealthy after 2 successes")
	}
	p.RecordUp("a")
	if !p.Healthy("a") {
		t.Fatalf("expected healthy after 3 successes")
	}
}

func TestPool_RecordDown_ReachesUnhealthy(t *testing.T) {
	t.Parallel()
	ups := []config.Upstream{{Name: "a", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"}}
	p := newPool(t, config.Health{FailThreshold: 2, SuccessThreshold: 1}, ups...)

	p.RecordUp("a") // 1 success, but already healthy initially
	if !p.Healthy("a") {
		t.Fatalf("expected healthy initially")
	}
	p.RecordDown("a")
	if !p.Healthy("a") {
		t.Fatalf("expected still healthy after 1 failure (threshold=2)")
	}
	p.RecordDown("a")
	if p.Healthy("a") {
		t.Fatalf("expected unhealthy after 2 failures")
	}
}

func TestPool_RecordUp_ResetsFailures(t *testing.T) {
	t.Parallel()
	ups := []config.Upstream{{Name: "a", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"}}
	p := newPool(t, config.Health{FailThreshold: 3, SuccessThreshold: 1}, ups...)

	p.RecordDown("a")
	p.RecordDown("a")
	// 2 failures, still healthy (threshold 3)
	p.RecordUp("a") // should reset failures
	p.RecordDown("a")
	p.RecordDown("a")
	if !p.Healthy("a") {
		t.Fatalf("expected healthy: 2 failures after reset, not enough for threshold")
	}
}

func TestPool_Replace(t *testing.T) {
	t.Parallel()
	initial := []config.Upstream{
		{Name: "a", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"},
		{Name: "b", Type: config.ProtocolHTTP, Address: "2.2.2.2:80"},
	}
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1}, initial...)
	p.RecordDown("a") // make a unhealthy

	// Replace with a new set: c added, b kept (state preserved), a removed.
	next := []config.Upstream{
		{Name: "b", Type: config.ProtocolHTTP, Address: "2.2.2.2:80", Username: "u"},
		{Name: "c", Type: config.ProtocolHTTP, Address: "3.3.3.3:80"},
	}
	p.Replace(next)

	// a is gone
	if p.Healthy("a") {
		t.Errorf("a should be removed")
	}
	// b kept (state preserved)
	if !p.Healthy("b") {
		t.Errorf("b should remain healthy after replace")
	}
	// c is new, healthy
	if !p.Healthy("c") {
		t.Errorf("c should be healthy after replace")
	}

	// Check the new address (b's Username) flowed through.
	ups := p.Snapshot()
	var found bool
	for _, u := range ups {
		if u.Name == "b" && u.Username == "u" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected b to have new Username=u, snapshot=%+v", ups)
	}
}

func TestPool_Replace_KeepByValue(t *testing.T) {
	// If the upstream is unchanged across replace, its entry is preserved.
	t.Parallel()
	ups := []config.Upstream{{Name: "a", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"}}
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1}, ups...)
	p.RecordDown("a")
	if p.Healthy("a") {
		t.Fatalf("setup: a should be unhealthy")
	}

	// Re-insert the same entry.
	p.Replace([]config.Upstream{ups[0]})
	if p.Healthy("a") {
		t.Fatalf("expected a to stay unhealthy across replace (same value)")
	}
}

func TestPool_SnapshotOrder(t *testing.T) {
	t.Parallel()
	ups := []config.Upstream{
		{Name: "z", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"},
		{Name: "a", Type: config.ProtocolHTTP, Address: "2.2.2.2:80"},
		{Name: "m", Type: config.ProtocolHTTP, Address: "3.3.3.3:80"},
	}
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1}, ups...)

	got := p.Snapshot()
	want := []string{"z", "a", "m"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Name != w {
			t.Errorf("position %d: got %q, want %q", i, got[i].Name, w)
		}
	}
}

func TestPool_Names(t *testing.T) {
	t.Parallel()
	ups := []config.Upstream{
		{Name: "u1", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"},
		{Name: "u2", Type: config.ProtocolSOCKS5, Address: "1.1.1.1:1080"},
	}
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1}, ups...)
	got := p.Names()
	if len(got) != 2 || got[0] != "u1" || got[1] != "u2" {
		t.Fatalf("Names = %v, want [u1 u2]", got)
	}
}

func TestPool_HealthyUnknown(t *testing.T) {
	t.Parallel()
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1})
	if p.Healthy("nope") {
		t.Fatalf("unknown name should be reported unhealthy")
	}
}

func TestPool_ForceHealthy(t *testing.T) {
	t.Parallel()
	ups := []config.Upstream{{Name: "a", Type: config.ProtocolHTTP, Address: "1.1.1.1:80"}}
	p := newPool(t, config.Health{FailThreshold: 1, SuccessThreshold: 1}, ups...)

	p.ForceHealthy("a", false)
	if p.Healthy("a") {
		t.Fatalf("ForceHealthy(false) should mark unhealthy")
	}
	p.ForceHealthy("a", true)
	if !p.Healthy("a") {
		t.Fatalf("ForceHealthy(true) should mark healthy")
	}
}
