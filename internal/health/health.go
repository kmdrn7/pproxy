// Package health runs periodic probes against every upstream in the pool and
// reports the outcome back to the pool's health state machine.
package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/kmdrn7/pproxy/internal/config"
	"github.com/kmdrn7/pproxy/internal/metrics"
	"github.com/kmdrn7/pproxy/internal/pool"
)

// defaultProbeURL is the destination used by HTTP probes. example.com is
// IANA-controlled, returns 200, and uses the default HTTP port (80), so
// strict forward proxies do not reject the request for a port-mismatch
// with the scheme. Operators can override the target in config if their
// network cannot reach example.com or requires a custom probe endpoint.
const defaultProbeURL = "http://example.com/"

// defaultProbeHost is the host:port used by SOCKS5 connect probes. The
// probe does a connect-only handshake (no payload), so the target just
// needs to accept a TCP connection on a commonly-permitted port.
const defaultProbeHost = "example.com:80"

// ProbeTargets holds the operator-overridable probe destinations.
type ProbeTargets struct {
	URL  string
	Host string
}

// probeTargets is the internal lowercase form used by the Scheduler.
type probeTargets struct {
	url  string
	host string
}

// toLower converts a public ProbeTargets to the internal form, applying
// defaults for any empty field.
func (t ProbeTargets) toLower() probeTargets {
	if t.URL == "" {
		t.URL = defaultProbeURL
	}
	if t.Host == "" {
		t.Host = defaultProbeHost
	}
	return probeTargets{url: t.URL, host: t.Host}
}

// Scheduler runs the per-upstream probe loop. It is safe to start exactly
// once and stop via context cancellation.
type Scheduler struct {
	pool    *pool.Pool
	health  config.Health
	targets probeTargets
	log     *slog.Logger

	requests chan string
}

// New builds a Scheduler using the default probe targets.
func New(p *pool.Pool, h config.Health, log *slog.Logger) *Scheduler {
	return NewWithTargets(p, h, ProbeTargets{}, log)
}

// NewWithTargets builds a Scheduler with explicit probe targets. The URL
// is used by HTTP probes; the Host is the host:port used by SOCKS5 connect
// probes. Empty strings fall back to the default.
func NewWithTargets(p *pool.Pool, h config.Health, t ProbeTargets, log *slog.Logger) *Scheduler {
	return &Scheduler{
		pool:     p,
		health:   h,
		targets:  t.toLower(),
		log:      log.With("component", "health"),
		requests: make(chan string, 64),
	}
}

// RequestImmediateProbe asks the scheduler to re-probe name at the next
// opportunity. It is non-blocking: if the request channel is full the call
// is dropped (the next periodic probe will pick it up).
func (s *Scheduler) RequestImmediateProbe(name string) {
	select {
	case s.requests <- name:
	default:
	}
}

// Run blocks until ctx is cancelled. The first probe of every upstream is
// run synchronously before the ticker starts so the pool has accurate state
// when listeners begin accepting traffic.
func (s *Scheduler) Run(ctx context.Context) error {
	for _, name := range s.pool.Names() {
		if ctx.Err() != nil {
			return nil
		}
		s.probeOne(ctx, name)
	}

	ticker := time.NewTicker(s.health.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for _, name := range s.pool.Names() {
				if ctx.Err() != nil {
					return nil
				}
				s.probeOne(ctx, name)
			}
		case name := <-s.requests:
			s.probeOne(ctx, name)
		}
	}
}

func (s *Scheduler) probeOne(parent context.Context, name string) {
	ups, ok := s.lookup(name)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(parent, s.health.Timeout)
	defer cancel()

	start := time.Now()
	err := s.probe(ctx, ups)
	metrics.HealthCheckLatency().WithLabelValues(ups.Name, string(ups.Type)).Observe(time.Since(start).Seconds())

	if err != nil {
		metrics.HealthCheckTotal().WithLabelValues(ups.Name, string(ups.Type), "fail").Inc()
		s.pool.RecordDown(ups.Name)
		s.log.Debug("health: probe failed", "upstream", ups.Name, "err", err)
		return
	}
	metrics.HealthCheckTotal().WithLabelValues(ups.Name, string(ups.Type), "ok").Inc()
	s.pool.RecordUp(ups.Name)
	s.log.Debug("health: probe ok", "upstream", ups.Name)
}

func (s *Scheduler) lookup(name string) (config.Upstream, bool) {
	for _, u := range s.pool.Snapshot() {
		if u.Name == name {
			return u, true
		}
	}
	return config.Upstream{}, false
}

func (s *Scheduler) probe(ctx context.Context, u config.Upstream) error {
	switch u.Type {
	case config.ProtocolHTTP:
		return s.probeHTTP(ctx, u)
	case config.ProtocolSOCKS5:
		return s.probeSOCKS5(ctx, u)
	default:
		return fmt.Errorf("health: unsupported type %q", u.Type)
	}
}

// dial opens a TCP (or TLS) connection to the upstream, respecting the
// per-upstream dialer configuration.
func dial(ctx context.Context, u config.Upstream) (net.Conn, error) {
	d := net.Dialer{Timeout: u.DialTimeout}
	if !u.TLS {
		return d.DialContext(ctx, "tcp", u.Address)
	}
	rootCAs, err := loadCAPool(u.CAFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		ServerName:         hostnameOf(u.Address),
		RootCAs:            rootCAs,
		InsecureSkipVerify: u.InsecureSkipVerify, //nolint:gosec // operator opt-in
		MinVersion:         tls.VersionTLS12,
	}
	rawConn, err := d.DialContext(ctx, "tcp", u.Address)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pem) {
		return nil, errors.New("ca_file: no certificates parsed")
	}
	return p, nil
}

func hostnameOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// probeHTTP sends a GET for the probe URL through the upstream HTTP proxy
// and treats any 2xx response as success. The URL is operator-configurable
// so deployments behind locked-down networks can point at an internal
// endpoint instead of example.com.
func (s *Scheduler) probeHTTP(ctx context.Context, u config.Upstream) error {
	conn, err := dial(ctx, u)
	if err != nil {
		return err
	}
	defer conn.Close()

	host := hostOnly(s.targets.url)
	req := "GET " + s.targets.url + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: pproxy-health/1\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n"
	if u.Username != "" {
		req += "Proxy-Authorization: Basic " + basicAuthHeader(u.Username, u.Password) + "\r\n"
	}
	req += "\r\n"

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := io.WriteString(conn, req); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return err
	}
	return assertStatus2xx(buf[:n])
}

// hostOnly extracts the host portion of a URL, stripping any path or query.
// For "http://example.com/foo" it returns "example.com".
func hostOnly(rawURL string) string {
	const sep = "://"
	i := strings.Index(rawURL, sep)
	if i < 0 {
		return rawURL
	}
	rest := rawURL[i+len(sep):]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		return rest[:j]
	}
	return rest
}

func assertStatus2xx(b []byte) error {
	const needle = "HTTP/1.1 2"
	if len(b) < len(needle) {
		return errors.New("health: short HTTP response")
	}
	if string(b[:len(needle)]) != needle {
		return fmt.Errorf("health: unexpected HTTP response: %q", firstLine(b))
	}
	return nil
}

func firstLine(b []byte) string {
	for i, c := range b {
		if c == '\n' {
			return string(b[:i])
		}
	}
	return string(b)
}

// probeSOCKS5 walks through a no-auth SOCKS5 handshake followed by a connect
// to the probe host. We deliberately do not exercise the upstream's auth
// method here; credentials are validated on the first real proxied request.
func (s *Scheduler) probeSOCKS5(ctx context.Context, u config.Upstream) error {
	conn, err := dial(ctx, u)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		return fmt.Errorf("socks5: handshake rejected: %#x", hdr[1])
	}

	host, port, err := net.SplitHostPort(s.targets.host)
	if err != nil {
		return err
	}
	pn, err := parsePort(port)
	if err != nil {
		return err
	}

	var atyp byte = 0x03
	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			atyp = 0x01
			addr = v4
		} else {
			atyp = 0x04
			addr = ip.To16()
		}
	} else {
		addr = []byte(host)
	}

	req := []byte{0x05, 0x01, 0x00, atyp}
	req = append(req, addr...)
	pb := [2]byte{}
	pb[0] = byte(pn >> 8)
	pb[1] = byte(pn & 0xff)
	req = append(req, pb[:]...)

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("socks5: connect refused: %#x", reply[1])
	}
	return nil
}

func parsePort(s string) (int, error) {
	var p int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid port")
		}
		p = p*10 + int(c-'0')
	}
	if p < 1 || p > 65535 {
		return 0, errors.New("port out of range")
	}
	return p, nil
}

func basicAuthHeader(u, p string) string {
	return base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
}
