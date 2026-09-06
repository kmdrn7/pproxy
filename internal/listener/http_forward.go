package listener

import (
	"bufio"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/metrics"
)

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
