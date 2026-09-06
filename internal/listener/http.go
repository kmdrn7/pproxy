package listener

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/metrics"
)

// HTTPListener accepts plain HTTP and HTTPS (CONNECT) traffic and forwards
// each connection through a single upstream chosen from the pool.
type HTTPListener struct {
	addr   string
	port   int
	proto  config.Protocol
	deps   Dependencies
	server *http.Server
	ln     net.Listener
}

// NewHTTP builds a listener bound to (addr, port).
func NewHTTP(addr string, port int, deps Dependencies) *HTTPListener {
	l := &HTTPListener{addr: addr, port: port, proto: config.ProtocolHTTP, deps: deps}
	l.server = &http.Server{
		Addr: net.JoinHostPort(addr, strconv.Itoa(port)),
		// We do not use http.ServeMux because Go 1.22+ method-aware
		// routing would not match CONNECT requests against a pattern
		// registered without a method constraint. The handler dispatches
		// internally based on r.Method.
		Handler:           http.HandlerFunc(l.handle),
		ReadHeaderTimeout: 30 * time.Second,
	}
	return l
}

// SetDeps atomically swaps the dependencies the listener reads on every
// request. The handler is a method value bound to the receiver, so this
// is enough to make subsequent requests use the new pool / auth store.
func (l *HTTPListener) SetDeps(deps Dependencies) {
	l.deps = deps
}

// Addr returns the bound address once Serve or ListenAndServe has been
// called. Before that it returns the configured address.
func (l *HTTPListener) Addr() string {
	if l.ln != nil {
		return l.ln.Addr().String()
	}
	return l.server.Addr
}

// Serve runs the listener on the supplied connection. Useful for tests
// that want to bind to a random port.
func (l *HTTPListener) Serve(ln net.Listener) error {
	l.ln = ln
	l.deps.Log.Info("listener: http serving", "addr", ln.Addr().String())
	if err := l.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		l.deps.Log.Error("listener: http serve", "err", err)
		return err
	}
	return nil
}

// ListenAndServe opens the listening socket on the configured address and
// serves until Shutdown is called.
func (l *HTTPListener) ListenAndServe() error {
	ln, err := net.Listen("tcp", l.server.Addr)
	if err != nil {
		return err
	}
	return l.Serve(ln)
}

// Shutdown stops accepting new connections and waits for in-flight requests
// to finish, bounded by ctx's deadline.
func (l *HTTPListener) Shutdown(ctx context.Context) error {
	return l.server.Shutdown(ctx)
}

// handle dispatches HTTP requests to the appropriate forwarder.
func (l *HTTPListener) handle(w http.ResponseWriter, r *http.Request) {
	metrics.ActiveConnections().WithLabelValues(string(l.proto), l.Addr()).Inc()
	defer metrics.ActiveConnections().WithLabelValues(string(l.proto), l.Addr()).Dec()
	l.deps.Log.Debug("http: request", "method", r.Method, "host", r.Host, "url", r.URL.String(), "remote", r.RemoteAddr)

	if !l.deps.Auth.Empty() {
		user, pass, ok := auth.ParseProxyAuthorization(r.Header.Get("Proxy-Authorization"))
		if !ok || !l.deps.Auth.Verify(user, pass) {
			auth.WriteProxyAuthRequired(w)
			return
		}
	}

	if r.Method == http.MethodConnect {
		l.handleConnect(w, r)
		return
	}
	l.handleForward(w, r)
}

// byteCountingWriter wraps an http.ResponseWriter and bumps a Prometheus
// counter for every byte written so the operator can see egress volume.
type byteCountingWriter struct {
	http.ResponseWriter
	counter prometheus.Counter
}

func (c *byteCountingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	if n > 0 {
		c.counter.Add(float64(n))
	}
	return n, err
}
