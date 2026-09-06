package listener

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/metrics"
)

// SOCKS5Listener accepts SOCKS5 client connections and forwards them through
// one of the registered SOCKS5 upstreams. It tracks in-flight connections so
// Shutdown can drain gracefully.
type SOCKS5Listener struct {
	addr  string
	port  int
	proto config.Protocol
	deps  Dependencies

	listener net.Listener
	active   atomic.Int64
	wg       sync.WaitGroup
}

// NewSOCKS5 builds a listener bound to (addr, port).
func NewSOCKS5(addr string, port int, deps Dependencies) *SOCKS5Listener {
	return &SOCKS5Listener{
		addr:  addr,
		port:  port,
		proto: config.ProtocolSOCKS5,
		deps:  deps,
	}
}

// SetDeps atomically swaps the dependencies the listener reads on every
// connection. The accept loop is already running; this just makes
// subsequent connections use the new pool / auth store / scheduler.
func (l *SOCKS5Listener) SetDeps(deps Dependencies) {
	l.deps = deps
}

// Addr returns the bound address once Serve or ListenAndServe has been
// called.
func (l *SOCKS5Listener) Addr() string {
	if l.listener != nil {
		return l.listener.Addr().String()
	}
	return net.JoinHostPort(l.addr, strconv.Itoa(l.port))
}

// Serve runs the listener on the supplied connection.
func (l *SOCKS5Listener) Serve(ln net.Listener) error {
	l.listener = ln
	l.deps.Log.Info("listener: socks5 serving", "addr", ln.Addr().String())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			l.deps.Log.Debug("socks5: accept error", "err", err)
			continue
		}
		l.wg.Add(1)
		l.active.Add(1)
		metrics.ActiveConnections().WithLabelValues(string(l.proto), ln.Addr().String()).Inc()
		go func(c net.Conn) {
			defer l.wg.Done()
			defer l.active.Add(-1)
			defer metrics.ActiveConnections().WithLabelValues(string(l.proto), ln.Addr().String()).Dec()
			l.handle(c)
		}(conn)
	}
}

// ListenAndServe opens the listening socket on the configured address and
// serves until Shutdown is called.
func (l *SOCKS5Listener) ListenAndServe() error {
	ln, err := net.Listen("tcp", net.JoinHostPort(l.addr, strconv.Itoa(l.port)))
	if err != nil {
		return err
	}
	return l.Serve(ln)
}

// Shutdown closes the listener and waits up to ctx's deadline for in-flight
// connections to finish.
func (l *SOCKS5Listener) Shutdown(ctx context.Context) error {
	if l.listener != nil {
		_ = l.listener.Close()
	}
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handle runs the SOCKS5 protocol state machine on a single client
// connection. All errors are reported back to the client per the RFC.
func (l *SOCKS5Listener) handle(clientConn net.Conn) {
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Minute))
	l.deps.Log.Debug("socks5: request", "remote", clientConn.RemoteAddr().String())

	methodReq, err := auth.ReadSOCKS5Methods(clientConn)
	if err != nil {
		l.deps.Log.Debug("socks5: read methods", "err", err)
		return
	}
	chosen := byte(0xFF) // no acceptable method
	if l.deps.Auth.Empty() && methodReq.HasMethod(0x00) {
		chosen = 0x00
	} else if !l.deps.Auth.Empty() && methodReq.HasMethod(0x02) {
		chosen = 0x02
	}
	if err := auth.WriteSOCKS5MethodResponse(clientConn, chosen); err != nil {
		return
	}
	if chosen == 0xFF {
		metrics.RequestsTotal().WithLabelValues(string(l.proto), "", "no_method").Inc()
		return
	}
	if chosen == 0x02 {
		if _, err := l.deps.Auth.AuthenticateSOCKS5(clientConn); err != nil {
			metrics.RequestsTotal().WithLabelValues(string(l.proto), "", "auth_fail").Inc()
			l.deps.Log.Debug("socks5: auth failed", "err", err)
			return
		}
	}

	req, err := auth.ReadSOCKS5Request(clientConn)
	if err != nil {
		l.deps.Log.Debug("socks5: read request", "err", err)
		return
	}
	if req.CMD != 0x01 {
		_ = auth.WriteSOCKS5Reply(clientConn, 0x07, net.IPv4zero, 0) // command not supported
		return
	}

	for _, name := range l.pickAttempts() {
		ups, found := l.lookupUpstream(name)
		if !found {
			continue
		}
		if l.tryForward(clientConn, req, ups) {
			metrics.RequestsTotal().WithLabelValues(string(l.proto), name, "ok").Inc()
			l.deps.Pool.RecordUp(name)
			return
		}
		metrics.RequestsTotal().WithLabelValues(string(l.proto), name, "error").Inc()
		l.deps.Pool.RecordDown(name)
		l.deps.Scheduler.RequestImmediateProbe(name)
		metrics.UpstreamFailures().WithLabelValues(name, "socks5").Inc()
	}
	_ = auth.WriteSOCKS5Reply(clientConn, 0x03, net.IPv4zero, 0) // network unreachable
}

func (l *SOCKS5Listener) pickAttempts() []string {
	const maxAttempts = 4
	seen := make(map[string]struct{}, maxAttempts)
	var out []string
	for i := 0; i < maxAttempts; i++ {
		ups, ok := l.deps.Pool.Next(config.ProtocolSOCKS5)
		if !ok {
			break
		}
		if _, dup := seen[ups.Name]; dup {
			break
		}
		seen[ups.Name] = struct{}{}
		out = append(out, ups.Name)
	}
	return out
}

func (l *SOCKS5Listener) lookupUpstream(name string) (config.Upstream, bool) {
	for _, u := range l.deps.Pool.Snapshot() {
		if u.Name == name {
			return u, true
		}
	}
	return config.Upstream{}, false
}
