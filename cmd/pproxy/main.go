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
}

type namedServer struct {
	name string
	srv  listener.Server
}

// activeRuntime holds the current runtime under a mutex so the config
// reload callback, the listener starter, and the shutdown path coordinate
// without races.
type activeRuntime struct {
	mu sync.RWMutex
	rt *runtime
}

func (a *activeRuntime) get() *runtime {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.rt
}

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
	rt, err := buildRuntime(initial, log)
	if err != nil {
		return err
	}
	active := &activeRuntime{rt: rt}

	sigCtx, sigCancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer sigCancel()

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)

	watcher := config.NewWatcher(*cfgPath, log, func(c *config.Config) {
		next, err := buildRuntime(c, log)
		if err != nil {
			log.Error("runtime: rebuild failed, keeping previous", "err", err)
			return
		}
		prev := active.swap(next)
		prev.shutdown(context.Background())
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

	healthCtx, healthCancel := context.WithCancel(context.Background())
	defer healthCancel()
	healthRef := newHealthRef(active, log)
	go func() {
		if err := healthRef.run(healthCtx); err != nil {
			log.Error("health: scheduler exited", "err", err)
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
	healthCancel()
	<-watchErr
	log.Info("shutdown: complete")
	return nil
}

// buildRuntime constructs the pool, auth, scheduler, and listeners from a
// validated config. It is the single integration point called both at
// startup and on every reload.
func buildRuntime(c *config.Config, log *slog.Logger) (*runtime, error) {
	store, err := auth.New(c.Auth.Users)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	p := pool.New(c.Pool, c.Health, log)
	sched := health.NewWithTargets(p, c.Health, health.ProbeTargets{URL: c.Health.ProbeURL, Host: c.Health.ProbeHost}, log)

	deps := listener.Dependencies{
		Pool:      p,
		Auth:      store,
		Scheduler: sched,
		Log:       log,
	}
	var servers []namedServer
	for _, l := range c.Listen {
		switch l.Protocol {
		case config.ProtocolHTTP, config.ProtocolHTTPS:
			ln := listener.NewHTTP(l.Address, l.Port, deps)
			servers = append(servers, namedServer{
				name: fmt.Sprintf("%s://%s:%d", l.Protocol, l.Address, l.Port),
				srv:  ln,
			})
		case config.ProtocolSOCKS5:
			ln := listener.NewSOCKS5(l.Address, l.Port, deps)
			servers = append(servers, namedServer{
				name: fmt.Sprintf("socks5://%s:%d", l.Address, l.Port),
				srv:  ln,
			})
		default:
			return nil, fmt.Errorf("listener: unsupported protocol %q", l.Protocol)
		}
	}
	return &runtime{pool: p, auth: store, scheduler: sched, servers: servers}, nil
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

// healthRef tracks the current runtime so the health scheduler can be
// rebuilt on config reload. It encapsulates the goroutine lifecycle.
type healthRef struct {
	active    *activeRuntime
	log       *slog.Logger
	current   atomic.Pointer[health.Scheduler]
	cancelRun context.CancelFunc
}

func newHealthRef(active *activeRuntime, log *slog.Logger) *healthRef {
	return &healthRef{active: active, log: log}
}

func (h *healthRef) run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	h.cancelRun = cancel
	rt := h.active.get()
	sched := rt.scheduler
	h.current.Store(sched)
	go func() {
		if err := sched.Run(ctx); err != nil {
			h.log.Error("health: scheduler exited", "err", err)
		}
	}()

	// No additional logic today; the hook is here so a future
	// enhancement can rebuild the scheduler on reload without touching
	// the call site in run().
	<-ctx.Done()
	return nil
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
