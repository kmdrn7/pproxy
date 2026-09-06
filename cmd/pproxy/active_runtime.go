package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/kmdrn7/pproxy/internal/health"
)

// activeRuntime holds the current runtime under a mutex so the config
// reload callback, the listener starter, and the shutdown path coordinate
// without races. The Prober shim reads the current scheduler through the
// same mutex via get(), so there is a single source of truth for what
// "current" means.
type activeRuntime struct {
	log *slog.Logger

	mu sync.RWMutex
	rt *runtime
}

func newActiveRuntime(log *slog.Logger) *activeRuntime {
	return &activeRuntime{log: log}
}

func (a *activeRuntime) get() *runtime {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.rt
}

// swap installs next as the current runtime and returns the previous one.
// Callers are responsible for stopping the previous scheduler and starting
// the next one around the swap.
func (a *activeRuntime) swap(next *runtime) *runtime {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.rt
	a.rt = next
	return prev
}

// startScheduler runs sched in the background. The scheduler owns its own
// goroutine lifetime; callers stop it via Scheduler.Stop.
func startScheduler(sched *health.Scheduler, log *slog.Logger) {
	go func() {
		if err := sched.Run(context.Background()); err != nil {
			log.Error("health: scheduler exited", "err", err)
		}
	}()
}

func startServers(active *activeRuntime, log *slog.Logger) <-chan error {
	rt := active.get()
	errs := make(chan error, len(rt.servers))
	for _, s := range rt.servers {
		s := s
		go func() {
			log.Info("listener: starting", "name", s.name)
			if err := s.srv.ListenAndServe(); err != nil {
				errs <- fmt.Errorf("listener %s: %w", s.name, err)
			}
		}()
	}
	return errs
}
