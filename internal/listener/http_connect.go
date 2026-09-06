package listener

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/metrics"
)

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
