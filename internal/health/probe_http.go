package health

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kmdrn7/pproxy/internal/config"
)

// probeHTTP sends a GET for the probe URL through the upstream HTTP proxy
// and treats any 2xx response as success.
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

func basicAuthHeader(u, p string) string {
	return base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
}
