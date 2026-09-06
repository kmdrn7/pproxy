package health

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
