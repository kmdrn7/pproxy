// Package listener hosts the inbound proxy servers. One file per protocol
// keeps the forwarding logic compact and reviewable.
package listener

import (
	"context"
	"log/slog"
	"net"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/pool"
)

// Dependencies bundles the collaborators required by every listener.
type Dependencies struct {
	Pool      *pool.Pool
	Auth      *auth.Store
	Scheduler Prober
	Log       *slog.Logger
}

// Prober is the minimal surface of *health.Scheduler that listeners depend
// on. Defined as an interface so tests can substitute a fake.
type Prober interface {
	RequestImmediateProbe(name string)
}

// Server is the interface implemented by every protocol listener. The
// orchestration code in main wires them up uniformly.
type Server interface {
	Addr() string
	// Serve runs the listener on the supplied connection. The caller is
	// responsible for opening the socket (e.g. net.Listen on a random
	// port for tests).
	Serve(net.Listener) error
	// ListenAndServe opens a socket on the configured address and serves
	// until Shutdown is called.
	ListenAndServe() error
	// Shutdown stops accepting new connections and waits for in-flight
	// requests to finish, bounded by ctx's deadline.
	Shutdown(ctx context.Context) error
	// SetDeps atomically swaps the dependencies the listener reads on
	// every request. Used by the hot-reload path so the same listener
	// socket keeps serving while the upstream pool / auth store /
	// scheduler change under it.
	SetDeps(Dependencies)
}
