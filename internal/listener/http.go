package listener

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	addr  string
	port  int
	proto config.Protocol
	deps  Dependencies
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

// handleForward proxies a plain HTTP request (with absolute URI form) to one
// or more upstreams in sequence. Try-next happens transparently on transport
// failures, matching the request-failure policy in the design.
func (l *HTTPListener) handleForward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "absolute URI required", http.StatusBadRequest)
		return
	}
	attempts := l.pickAttempts()
	if len(attempts) == 0 {
		metrics.RequestsTotal().WithLabelValues(string(l.proto), "", "no_upstream").Inc()
		http.Error(w, "no healthy upstream", http.StatusServiceUnavailable)
		return
	}

	for _, name := range attempts {
		ups, ok := l.lookupUpstream(name)
		if !ok {
			continue
		}
		if l.tryForward(w, r, ups) {
			metrics.RequestsTotal().WithLabelValues(string(l.proto), name, "ok").Inc()
			l.deps.Pool.RecordUp(name)
			return
		}
		metrics.RequestsTotal().WithLabelValues(string(l.proto), name, "error").Inc()
		l.deps.Pool.RecordDown(name)
		l.deps.Scheduler.RequestImmediateProbe(name)
		metrics.UpstreamFailures().WithLabelValues(name, "request").Inc()
	}
	http.Error(w, "all upstreams failed: check pproxy config (pool section) and upstream health", http.StatusBadGateway)
}

func (l *HTTPListener) tryForward(w http.ResponseWriter, r *http.Request, ups config.Upstream) bool {
	conn, err := dialUpstream(r.Context(), ups)
	if err != nil {
		l.deps.Log.Debug("http: dial upstream failed", "upstream", ups.Name, "err", err)
		return false
	}
	defer conn.Close()

	if dl, ok := r.Context().Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	// Clone the request so we can attach the upstream Proxy-Authorization
	// header without mutating the caller's request.
	forward := r.Clone(r.Context())
	if ups.Username != "" {
		forward.Header.Set("Proxy-Authorization", "Basic "+basicAuth(ups.Username, ups.Password))
	}

	start := time.Now()
	// Go 1.26 changed Request.Write to default to usingProxy=false (relative
	// URI). We are forwarding through another proxy, so use WriteProxy to
	// emit the absolute URI in the request line.
	if err := forward.WriteProxy(conn); err != nil {
		l.deps.Log.Debug("http: write request failed", "upstream", ups.Name, "err", err)
		return false
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), forward)
	if err != nil {
		l.deps.Log.Debug("http: read response failed", "upstream", ups.Name, "err", err)
		return false
	}
	defer resp.Body.Close()
	metrics.RequestDuration().WithLabelValues(string(l.proto), ups.Name).Observe(time.Since(start).Seconds())

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	cw := &byteCountingWriter{
		ResponseWriter: w,
		counter:        metrics.BytesTransferred().WithLabelValues(string(l.proto), ups.Name, "upstream_to_client"),
	}
	_, _ = io.Copy(cw, resp.Body)
	return true
}

// handleConnect implements the HTTP CONNECT tunnel method.
func (l *HTTPListener) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	for _, name := range l.pickAttempts() {
		ups, found := l.lookupUpstream(name)
		if !found {
			continue
		}
		if l.tryConnect(clientConn, r, ups) {
			metrics.RequestsTotal().WithLabelValues(string(l.proto), name, "ok").Inc()
			l.deps.Pool.RecordUp(name)
			return
		}
		metrics.RequestsTotal().WithLabelValues(string(l.proto), name, "error").Inc()
		l.deps.Pool.RecordDown(name)
		l.deps.Scheduler.RequestImmediateProbe(name)
		metrics.UpstreamFailures().WithLabelValues(name, "connect").Inc()
	}
	l.writeConnectError(clientConn, http.StatusBadGateway, "no healthy upstream proxy")
}

// writeConnectError writes an HTTP-style error response on a hijacked
// connection. Used after CONNECT when no upstream succeeded.
func (l *HTTPListener) writeConnectError(conn net.Conn, status int, body string) {
	reason := http.StatusText(status)
	if l.deps.Pool.SnapshotSize() == 0 {
		reason = "no upstreams configured in pproxy"
	} else if l.deps.Pool.HealthyCount() == 0 {
		reason = "no healthy upstream (all marked unhealthy by recent failures)"
	}
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: %d\r\nProxy-Agent: pproxy\r\n\r\n%s",
		status, reason, len(body), body)
	_, _ = conn.Write([]byte(resp))
}

func (l *HTTPListener) tryConnect(clientConn net.Conn, r *http.Request, ups config.Upstream) bool {
	upstreamConn, err := dialUpstream(r.Context(), ups)
	if err != nil {
		l.deps.Log.Debug("connect: dial upstream failed", "upstream", ups.Name, "err", err)
		return false
	}
	defer upstreamConn.Close()

	// Build the CONNECT request with the upstream auth header in the same
	// frame. A separate "auth" CONNECT would tunnel the connection to the
	// throwaway target and leave subsequent bytes routed to that target
	// instead of the proxy.
	connectReq := "CONNECT " + r.URL.Host + " HTTP/1.1\r\nHost: " + r.URL.Host + "\r\n"
	if ups.Username != "" {
		connectReq += "Proxy-Authorization: Basic " + basicAuth(ups.Username, ups.Password) + "\r\n"
	}
	connectReq += "\r\n"
	if _, err := io.WriteString(upstreamConn, connectReq); err != nil {
		l.deps.Log.Debug("connect: write request failed", "upstream", ups.Name, "err", err)
		return false
	}
	br := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		l.deps.Log.Debug("connect: read response failed", "upstream", ups.Name, "err", err)
		return false
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		l.deps.Log.Debug("connect: upstream refused", "upstream", ups.Name, "status", resp.StatusCode)
		return false
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: pproxy\r\n\r\n")); err != nil {
		return false
	}
	pump(clientConn, upstreamConn, string(l.proto), ups.Name, l.deps.Log)
	return true
}

// pump copies bytes in both directions between client and upstream,
// closing the connection when either side returns an error.
func pump(client, upstream net.Conn, proto, upstreamName string, log *slog.Logger) {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, client)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(client, upstream)
		errCh <- err
	}()
	<-errCh
	_ = client.Close()
	_ = upstream.Close()
}

// pickAttempts returns up to maxAttempts distinct upstream names, in
// round-robin order, skipping duplicates so try-next explores the pool.
func (l *HTTPListener) pickAttempts() []string {
	const maxAttempts = 4
	seen := make(map[string]struct{}, maxAttempts)
	var out []string
	for i := 0; i < maxAttempts; i++ {
		ups, ok := l.deps.Pool.Next(config.ProtocolHTTP)
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

func (l *HTTPListener) lookupUpstream(name string) (config.Upstream, bool) {
	for _, u := range l.deps.Pool.Snapshot() {
		if u.Name == name {
			return u, true
		}
	}
	return config.Upstream{}, false
}

func basicAuth(u, p string) string {
	return base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
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
