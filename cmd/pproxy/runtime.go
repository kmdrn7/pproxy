package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/health"
	"github.com/kmdrn7/pproxy/internal/listener"
	"github.com/kmdrn7/pproxy/internal/pool"
)

// runtime is the per-process bag of collaborators. It is rebuilt atomically
// on every config reload so a bad config never leaves the process in a
// half-updated state.
type runtime struct {
	pool      *pool.Pool
	auth      *auth.Store
	scheduler *health.Scheduler
	servers   []namedServer
	// active is the swap-handle that owns this runtime. Held so the
	// Prober shim can resolve to whichever scheduler is currently
	// registered (i.e. this one, until the next swap).
	active *activeRuntime
}

// Prober returns a listener.Prober that dispatches to whichever scheduler
// is current in the active runtime.
func (r *runtime) Prober() listener.Prober {
	return proberFunc(func(name string) { r.active.get().scheduler.RequestImmediateProbe(name) })
}

// proberFunc adapts a function to the listener.Prober interface so callers
// can construct a fresh value on every request without an allocation.
type proberFunc func(name string)

func (f proberFunc) RequestImmediateProbe(name string) { f(name) }

// depsForListeners builds the Dependencies block passed to listeners;
// SetDeps swaps in a fresh one on every reload.
func (r *runtime) depsForListeners() listener.Dependencies {
	return listener.Dependencies{
		Pool:      r.pool,
		Auth:      r.auth,
		Scheduler: r.Prober(),
		Log:       r.active.log,
	}
}

type namedServer struct {
	name string
	srv  listener.Server
}

// buildRuntime constructs the pool, auth, scheduler, and listeners from a
// validated config. The returned runtime is not yet active; callers wire
// it into activeRuntime and start the scheduler.
func buildRuntime(c *config.Config, active *activeRuntime) (*runtime, error) {
	log := active.log
	store, err := auth.New(c.Auth.Users)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	p := pool.New(c.Pool, c.Health, log)
	sched := health.NewWithTargets(p, c.Health, health.ProbeTargets{URL: c.Health.ProbeURL, Host: c.Health.ProbeHost}, log)

	rt := &runtime{pool: p, auth: store, scheduler: sched, active: active}

	var servers []namedServer
	for _, l := range c.Listen {
		switch l.Protocol {
		case config.ProtocolHTTP, config.ProtocolHTTPS:
			ln := listener.NewHTTP(l.Address, l.Port, rt.depsForListeners())
			servers = append(servers, namedServer{
				name: fmt.Sprintf("%s://%s:%d", l.Protocol, l.Address, l.Port),
				srv:  ln,
			})
		case config.ProtocolSOCKS5:
			ln := listener.NewSOCKS5(l.Address, l.Port, rt.depsForListeners())
			servers = append(servers, namedServer{
				name: fmt.Sprintf("socks5://%s:%d", l.Address, l.Port),
				srv:  ln,
			})
		default:
			return nil, fmt.Errorf("listener: unsupported protocol %q", l.Protocol)
		}
	}
	rt.servers = servers
	return rt, nil
}

func (r *runtime) shutdown(ctx context.Context) {
	if r == nil {
		return
	}
	var wg sync.WaitGroup
	for _, s := range r.servers {
		wg.Add(1)
		go func(srv listener.Server) {
			defer wg.Done()
			_ = srv.Shutdown(ctx)
		}(s.srv)
	}
	wg.Wait()
}

// reconcileListeners swaps deps on surviving listeners, starts new ones,
// and stops removed ones — no port flap.
func reconcileListeners(prev, next *runtime, log *slog.Logger) {
	oldByName := make(map[string]namedServer, len(prev.servers))
	for _, s := range prev.servers {
		oldByName[s.name] = s
	}
	for _, ns := range next.servers {
		old, ok := oldByName[ns.name]
		if !ok {
			// Brand new listener (e.g. user added an http listener on
			// 8081). Start it.
			go func(s namedServer) {
				log.Info("listener: starting", "name", s.name)
				if err := s.srv.ListenAndServe(); err != nil {
					log.Error("listener: serve", "name", s.name, "err", err)
				}
			}(ns)
			continue
		}
		// Same listener, same address: keep the socket open and just
		// push the new deps. The handler reads deps on every request, so
		// in-flight requests finish with the old pool and new ones use
		// the new pool — there is no port flap.
		old.srv.SetDeps(next.depsForListeners())
		delete(oldByName, ns.name)
	}
	// Anything left was removed from the config; stop it.
	for _, s := range oldByName {
		log.Info("listener: stopping", "name", s.name)
		go func(srv listener.Server) {
			_ = srv.Shutdown(context.Background())
		}(s.srv)
	}
}
