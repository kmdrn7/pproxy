// Package pool owns the upstream registry, round-robin selection, and the
// hot-replace operation that supports config reloads without dropping traffic.
package pool

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/metrics"
)

// state encodes the per-upstream health lifecycle.
type state int32

const (
	stateHealthy   state = 1
	stateUnhealthy state = 2
)

// entry is the runtime representation of a single Upstream.
type entry struct {
	upstream            config.Upstream
	state               atomic.Int32
	consecutiveFailures atomic.Int32
	consecutiveSuccesses atomic.Int32
}

func (e *entry) healthy() bool {
	return state(e.state.Load()) == stateHealthy
}

// Pool is a concurrent-safe registry of upstreams with round-robin selection.
type Pool struct {
	log    *slog.Logger
	health config.Health

	mu      sync.RWMutex
	entries map[string]*entry
	order   []*entry
	rr      atomic.Uint64
}

// New builds a Pool from the validated config slice. The health thresholds
// drive both the periodic prober and the request-time mark functions.
func New(upstreams []config.Upstream, health config.Health, log *slog.Logger) *Pool {
	p := &Pool{log: log, health: health, entries: make(map[string]*entry, len(upstreams))}
	p.replaceLocked(upstreams)
	for _, e := range p.order {
		metrics.UpstreamHealthy().WithLabelValues(e.upstream.Name, string(e.upstream.Type)).Set(1)
	}
	return p
}

// replaceLocked rebuilds the registry from upstreams. The caller must hold
// p.mu for writing; on the first call (from New) the lock is implicitly
// uncontested so this is safe.
func (p *Pool) replaceLocked(upstreams []config.Upstream) {
	previous := make(map[string]*entry, len(p.order))
	for _, e := range p.order {
		previous[e.upstream.Name] = e
	}
	p.entries = make(map[string]*entry, len(upstreams))
	p.order = p.order[:0]
	for _, u := range upstreams {
		if e, ok := previous[u.Name]; ok && e.upstream == u {
			p.entries[u.Name] = e
			p.order = append(p.order, e)
			continue
		}
		e := &entry{upstream: u}
		e.state.Store(int32(stateHealthy))
		p.entries[u.Name] = e
		p.order = append(p.order, e)
		metrics.UpstreamHealthy().WithLabelValues(u.Name, string(u.Type)).Set(1)
	}
}

// Snapshot returns a copy of the current upstreams for display or logging.
func (p *Pool) Snapshot() []config.Upstream {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]config.Upstream, len(p.order))
	for i, e := range p.order {
		out[i] = e.upstream
	}
	return out
}

// SnapshotSize returns the number of upstreams currently registered.
func (p *Pool) SnapshotSize() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.order)
}

// HealthyCount returns the number of upstreams currently marked healthy.
func (p *Pool) HealthyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, e := range p.order {
		if e.healthy() {
			n++
		}
	}
	return n
}

// Replace atomically swaps the registry. Upstreams that disappear are dropped;
// new ones start in the healthy state. Existing entries keep their state.
func (p *Pool) Replace(upstreams []config.Upstream) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.replaceLocked(upstreams)
}

// Next returns the next healthy upstream of the requested protocol using a
// round-robin cursor that skips unhealthy entries. The bool result is false
// when no healthy upstream is available for the protocol.
func (p *Pool) Next(protocol config.Protocol) (*config.Upstream, bool) {
	p.mu.RLock()
	n := len(p.order)
	if n == 0 {
		p.mu.RUnlock()
		return nil, false
	}
	// Take a local copy of the order slice so we can release the lock while
	// scanning. Entries are stable pointers; the slice itself is the only
	// thing that can change under Replace.
	order := append([]*entry(nil), p.order...)
	p.mu.RUnlock()

	start := p.rr.Add(1) - 1
	for i := 0; i < n; i++ {
		idx := (int(start) + i) % n
		e := order[idx]
		if e.upstream.Type != protocol {
			continue
		}
		if !e.healthy() {
			continue
		}
		u := e.upstream
		return &u, true
	}
	return nil, false
}

// RecordUp marks a successful use (probe or proxied request) of name. After
// the configured number of consecutive successes the upstream transitions to
// the healthy state.
func (p *Pool) RecordUp(name string) {
	e, ok := p.get(name)
	if !ok {
		return
	}
	e.consecutiveFailures.Store(0)
	s := e.consecutiveSuccesses.Add(1)
	if s >= int32(p.health.SuccessThreshold) {
		e.state.Store(int32(stateHealthy))
		metrics.UpstreamHealthy().WithLabelValues(e.upstream.Name, string(e.upstream.Type)).Set(1)
	}
}

// RecordDown marks a failed use of name. After the configured number of
// consecutive failures the upstream transitions to the unhealthy state.
func (p *Pool) RecordDown(name string) {
	e, ok := p.get(name)
	if !ok {
		return
	}
	e.consecutiveSuccesses.Store(0)
	f := e.consecutiveFailures.Add(1)
	if f >= int32(p.health.FailThreshold) {
		e.state.Store(int32(stateUnhealthy))
		metrics.UpstreamHealthy().WithLabelValues(e.upstream.Name, string(e.upstream.Type)).Set(0)
	}
}

// ForceHealthy overrides the state of name. Used by the health scheduler when
// it wants to seed the initial state from a startup probe sweep.
func (p *Pool) ForceHealthy(name string, healthy bool) {
	e, ok := p.get(name)
	if !ok {
		return
	}
	if healthy {
		e.consecutiveFailures.Store(0)
		e.consecutiveSuccesses.Store(int32(p.health.SuccessThreshold))
		e.state.Store(int32(stateHealthy))
		metrics.UpstreamHealthy().WithLabelValues(e.upstream.Name, string(e.upstream.Type)).Set(1)
		return
	}
	e.consecutiveSuccesses.Store(0)
	e.consecutiveFailures.Store(int32(p.health.FailThreshold))
	e.state.Store(int32(stateUnhealthy))
	metrics.UpstreamHealthy().WithLabelValues(e.upstream.Name, string(e.upstream.Type)).Set(0)
}

// Healthy reports the current state of name. Unregistered names are reported
// unhealthy so the call can be used as a safety check.
func (p *Pool) Healthy(name string) bool {
	e, ok := p.get(name)
	if !ok {
		return false
	}
	return e.healthy()
}

// Names returns the registered upstream names in deterministic order.
func (p *Pool) Names() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, len(p.order))
	for i, e := range p.order {
		out[i] = e.upstream.Name
	}
	return out
}

// ErrNoHealthyUpstream is returned by helpers that want to surface a typed
// "all upstreams for the protocol are down" condition.
var ErrNoHealthyUpstream = errors.New("pool: no healthy upstream for protocol")

func (p *Pool) get(name string) (*entry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.entries[name]
	return e, ok
}
