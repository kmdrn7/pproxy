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
	"syscall"
	"time"

	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/logger"
	"github.com/kmdrn7/pproxy/internal/metrics"
)

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
	active := newActiveRuntime(log)
	rt, err := buildRuntime(initial, active)
	if err != nil {
		return err
	}
	active.swap(rt)
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
		// Start the new scheduler and make it current before stopping the
		// old one, so there is no window where an immediate-probe request
		// is dropped because neither scheduler is running yet.
		startScheduler(next.scheduler, log)
		prev := active.swap(next)
		// Stop the previous scheduler in the background: it can block on
		// an in-flight probe, and that must not delay the listener-deps
		// update below.
		go prev.scheduler.Stop()
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
	active.get().scheduler.Stop()
	<-watchErr
	log.Info("shutdown: complete")
	return nil
}
