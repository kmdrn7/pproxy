package listener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/kmdrn7/pproxy/internal/config"
)

// dialUpstream opens a TCP (or TLS) connection to the upstream, applying the
// per-upstream dialer configuration. It is the single chokepoint for talking
// to the proxy pool, used by both the HTTP and SOCKS5 listeners.
func dialUpstream(ctx context.Context, u config.Upstream) (net.Conn, error) {
	d := net.Dialer{Timeout: u.DialTimeout}
	if !u.TLS {
		return d.DialContext(ctx, "tcp", u.Address)
	}
	rootCAs, err := loadUpstreamCAPool(u.CAFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		ServerName:         hostnameOf(u.Address),
		RootCAs:            rootCAs,
		InsecureSkipVerify: u.InsecureSkipVerify, //nolint:gosec // operator opt-in
		MinVersion:         tls.VersionTLS12,
	}
	raw, err := d.DialContext(ctx, "tcp", u.Address)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tlsConn, nil
}

func loadUpstreamCAPool(path string) (*x509.CertPool, error) {
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
