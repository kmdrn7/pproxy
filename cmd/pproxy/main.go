package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/health"
	"github.com/kmdrn7/pproxy/internal/listener"
	"github.com/kmdrn7/pproxy/internal/logger"
	"github.com/kmdrn7/pproxy/internal/metrics"
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
// is current in the active runtime. The indirection is what lets the
// listener side keep using the same Dependencies value across reloads
// while the underlying scheduler is rebuilt underneath it.
func (r *runtime) Prober() listener.Prober {
	return proberFunc(func(name string) { r.active.scheduler().RequestImmediateProbe(name) })
}

// proberFunc adapts a function to the listener.Prober interface so callers
// can construct a fresh value on every request without an allocation.
type proberFunc func(name string)

func (f proberFunc) RequestImmediateProbe(name string) { f(name) }

// depsForListeners builds a Dependencies block that holds the same pool,
// auth, log, and Prober shim that survives across reloads via SetDeps.
// The pool and auth are passed by value here; the listener captures them
// by reference inside Dependencies, so a SetDeps swaps in the new ones.
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

// activeRuntime holds the current runtime under a mutex so the config
// reload callback, the listener starter, and the shutdown path coordinate
// without races. The scheduler pointer is tracked separately so the
// Prober shim can dispatch to the current scheduler without taking the
// mutex on the request hot path.
type activeRuntime struct {
	log *slog.Logger

	mu     sync.RWMutex
	rt     *runtime
	sched  atomic.Pointer[health.Scheduler]
}

func newActiveRuntime(log *slog.Logger, rt *runtime) *activeRuntime {
	a := &activeRuntime{log: log}
	a.rt = rt
	a.sched.Store(rt.scheduler)
	return a
}

func (a *activeRuntime) get() *runtime {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.rt
}

// scheduler returns the currently-active scheduler. The Prober shim uses
// this to dispatch immediate-probe requests without taking the runtime
// mutex.
func (a *activeRuntime) scheduler() *health.Scheduler {
	return a.sched.Load()
}

// setScheduler atomically updates the scheduler the Prober shim dispatches
// to. Called by the swap path after the new runtime is in place.
func (a *activeRuntime) setScheduler(s *health.Scheduler) {
	a.sched.Store(s)
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "pproxy:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", envOr("PPROXY_CONFIG", "config.yaml"), "path to YAML config")
	flag.Parse()

	bootLog := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	initial, err := config.Load(*cfgPath)
	if err != nil {
		bootLog.Error("load config failed", "err", err)
		return fmt.Errorf("load config: %w", err)
	}
	log := logger.New(logger.Options{Level: initial.Logging.Level, Format: initial.Logging.Format}).With("app", "pproxy")

	// Initial runtime is built once; the config watcher handles subsequent
	// swaps. This avoids a race where the watcher fires "startup" reload
	// before the initial listeners are wired up.
	active := newActiveRuntime(log, nil)
	rt, err := buildRuntime(initial, active)
	if err != nil {
		return err
	}
	active.installInitial(rt)
	startScheduler(rt.scheduler, log)

	sigCtx, sigCancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer sigCancel()

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)

	watcher := config.NewWatcher(*cfgPath, log, func(c *config.Config) {
		next, err := buildRuntime(c, active)
		if err != nil {
			log.Error("runtime: rebuild failed, keeping previous", "err", err)
			return
		}
		prev := active.swap(next)
		// Stop the previous scheduler so its goroutine and probe state are
		// released, then install the new one and point the Prober shim at
		// it. Listener deps are swapped separately below so the new pool
		// is visible on the next request.
		prev.scheduler.Stop()
		startScheduler(next.scheduler, log)
		active.setScheduler(next.scheduler)
		// Update deps on the existing listeners rather than shutting them
		// down. The handler is a method value bound to the receiver, so
		// swapping deps is enough to make subsequent requests use the new
		// pool / auth store. The TCP sockets stay bound, so the reload
		// is invisible to clients. Listeners that were added or removed
		// in the new config are reconciled below.
		reconcileListeners(prev, next, log)
		log.Info("runtime: swapped", "listeners", len(next.servers), "upstreams", len(next.pool.Snapshot()))
	})

	watchCtx, watchCancel := context.WithCancel(context.Background())
	defer watchCancel()
	watchErr := make(chan error, 1)
	go func() { watchErr <- watcher.Run(watchCtx, relay(reloadCh)) }()

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", metrics.Handler())
	metricsSrv := &http.Server{
		Addr:              initial.Server.MetricsAddress,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Info("metrics: serving", "addr", initial.Server.MetricsAddress)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics: server", "err", err)
		}
	}()

	listenErrs := startServers(active, log)

	select {
	case <-sigCtx.Done():
		log.Info("shutdown: signal received")
	case err := <-listenErrs:
		if err != nil {
			log.Error("listener: fatal", "err", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), initial.Server.ShutdownTimeout)
	defer shutdownCancel()

	_ = metricsSrv.Shutdown(shutdownCtx)
	active.get().shutdown(shutdownCtx)
	watchCancel()
	// The current scheduler is stopped after listeners so no probe fires
	// during drain.
	active.scheduler().Stop()
	<-watchErr
	log.Info("shutdown: complete")
	return nil
}

// buildRuntime constructs the pool, auth, scheduler, and listeners from a
// validated config. It is the single integration point called both at
// startup and on every reload. The returned runtime is not yet active;
// callers wire it into the activeRuntime and start the scheduler.
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

// installInitial records rt as the active runtime and points the Prober
// shim at its scheduler. Used once at startup; subsequent reloads go
// through swap + setScheduler.
func (a *activeRuntime) installInitial(rt *runtime) {
	a.mu.Lock()
	a.rt = rt
	a.mu.Unlock()
	a.sched.Store(rt.scheduler)
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

// reconcileListeners swaps the deps on listeners that survive the reload
// (same protocol + addr + port) so they keep serving on the same TCP
// socket, starts listeners that are new, and stops listeners that are
// gone. This is the hot-reload seam — the old runtime's listeners are
// reused wherever possible so there is no port flap.
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

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func relay(in <-chan os.Signal) <-chan struct{} {
	out := make(chan struct{}, 1)
	go func() {
		for range in {
			select {
			case out <- struct{}{}:
			default:
			}
		}
		close(out)
	}()
	return out
}
