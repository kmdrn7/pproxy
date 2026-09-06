// Package health runs periodic probes against every upstream in the pool and
// reports the outcome back to the pool's health state machine.
package health

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/metrics"
	"github.com/kmdrn7/pproxy/internal/pool"
)

// defaultProbeURL is the destination used by HTTP probes. example.com is
// IANA-controlled, returns 200, and uses the default HTTP port (80), so
// strict forward proxies do not reject the request for a port-mismatch
// with the scheme. Operators can override the target in config if their
// network cannot reach example.com or requires a custom probe endpoint.
const defaultProbeURL = "http://example.com/"

// defaultProbeHost is the host:port used by SOCKS5 connect probes. The
// probe does a connect-only handshake (no payload), so the target just
// needs to accept a TCP connection on a commonly-permitted port.
const defaultProbeHost = "example.com:80"

// ProbeTargets holds the operator-overridable probe destinations.
type ProbeTargets struct {
	URL  string
	Host string
}

// probeTargets is the internal lowercase form used by the Scheduler.
type probeTargets struct {
	url  string
	host string
}

// toLower converts a public ProbeTargets to the internal form, applying
// defaults for any empty field.
func (t ProbeTargets) toLower() probeTargets {
	if t.URL == "" {
		t.URL = defaultProbeURL
	}
	if t.Host == "" {
		t.Host = defaultProbeHost
	}
	return probeTargets{url: t.URL, host: t.Host}
}

// Scheduler runs the per-upstream probe loop. It is safe to start exactly
// once and stop via Stop (or context cancellation passed to Run).
type Scheduler struct {
	pool    *pool.Pool
	health  config.Health
	targets probeTargets
	log     *slog.Logger

	requests chan string

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New builds a Scheduler using the default probe targets.
func New(p *pool.Pool, h config.Health, log *slog.Logger) *Scheduler {
	return NewWithTargets(p, h, ProbeTargets{}, log)
}

// NewWithTargets builds a Scheduler with explicit probe targets. The URL
// is used by HTTP probes; the Host is the host:port used by SOCKS5 connect
// probes. Empty strings fall back to the default.
func NewWithTargets(p *pool.Pool, h config.Health, t ProbeTargets, log *slog.Logger) *Scheduler {
	return &Scheduler{
		pool:     p,
		health:   h,
		targets:  t.toLower(),
		log:      log.With("component", "health"),
		requests: make(chan string, 64),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Stop signals the scheduler to exit and waits for Run to return. Safe to
// call multiple times and from any goroutine. Used on config reload so the
// new scheduler can take over without leaking the previous goroutine.
func (s *Scheduler) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
	<-s.done
}

// RequestImmediateProbe asks the scheduler to re-probe name at the next
// opportunity. It is non-blocking: if the request channel is full the call
// is dropped (the next periodic probe will pick it up).
func (s *Scheduler) RequestImmediateProbe(name string) {
	select {
	case s.requests <- name:
	default:
	}
}

// Run blocks until ctx is cancelled or Stop is called. The first probe of
// every upstream is run synchronously before the ticker starts so the pool
// has accurate state when listeners begin accepting traffic.
func (s *Scheduler) Run(ctx context.Context) error {
	defer close(s.done)
	for _, name := range s.pool.Names() {
		if ctx.Err() != nil {
			return nil
		}
		s.probeOne(ctx, name)
	}

	ticker := time.NewTicker(s.health.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.stop:
			return nil
		case <-ticker.C:
			for _, name := range s.pool.Names() {
				if ctx.Err() != nil {
					return nil
				}
				s.probeOne(ctx, name)
			}
		case name := <-s.requests:
			s.probeOne(ctx, name)
		}
	}
}

func (s *Scheduler) probeOne(parent context.Context, name string) {
	ups, ok := s.lookup(name)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(parent, s.health.Timeout)
	defer cancel()

	start := time.Now()
	err := s.probe(ctx, ups)
	metrics.HealthCheckLatency().WithLabelValues(ups.Name, string(ups.Type)).Observe(time.Since(start).Seconds())

	if err != nil {
		metrics.HealthCheckTotal().WithLabelValues(ups.Name, string(ups.Type), "fail").Inc()
		s.pool.RecordDown(ups.Name)
		s.log.Debug("health: probe failed", "upstream", ups.Name, "err", err)
		return
	}
	metrics.HealthCheckTotal().WithLabelValues(ups.Name, string(ups.Type), "ok").Inc()
	s.pool.RecordUp(ups.Name)
	s.log.Debug("health: probe ok", "upstream", ups.Name)
}

func (s *Scheduler) lookup(name string) (config.Upstream, bool) {
	for _, u := range s.pool.Snapshot() {
		if u.Name == name {
			return u, true
		}
	}
	return config.Upstream{}, false
}

func (s *Scheduler) probe(ctx context.Context, u config.Upstream) error {
	switch u.Type {
	case config.ProtocolHTTP:
		return s.probeHTTP(ctx, u)
	case config.ProtocolSOCKS5:
		return s.probeSOCKS5(ctx, u)
	default:
		return fmt.Errorf("health: unsupported type %q", u.Type)
	}
}
