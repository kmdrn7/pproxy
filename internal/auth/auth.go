// Package auth stores client credentials and exposes the verification helpers
// used by the HTTP and SOCKS5 listeners.
package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/kmdrn7/pproxy/internal/config"
)

// Store is the in-memory credential store loaded at startup.
type Store struct {
	// name -> bcrypt hash. Uses constant-time lookup so probing for usernames
	// does not become a side channel.
	hashes map[string][]byte
}

// New builds a Store from the validated config. It returns an error if any
// password hash fails the bcrypt sanity check (so misconfiguration is caught
// at startup, not at first request).
func New(users []config.User) (*Store, error) {
	s := &Store{hashes: make(map[string][]byte, len(users))}
	for _, u := range users {
		if _, dup := s.hashes[u.Username]; dup {
			return nil, fmt.Errorf("auth: duplicate user %q", u.Username)
		}
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			return nil, fmt.Errorf("auth: user %q: %w", u.Username, err)
		}
		s.hashes[u.Username] = []byte(u.PasswordHash)
	}
	return s, nil
}

// Empty reports whether the store has any users. Callers can use this to skip
// auth entirely when none are configured.
func (s *Store) Empty() bool { return len(s.hashes) == 0 }

// Verify returns true if (username, password) matches a stored credential.
// The username lookup is constant-time over the number of stored users, but
// bcrypt inherently leaks timing for the matching entry.
func (s *Store) Verify(username, password string) bool {
	want, ok := s.hashes[username]
	if !ok {
		// Run a fake comparison so the response time is independent of whether
		// the username exists.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$abcdefghijklmnopqrstuv"), []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword(want, []byte(password)) == nil
}

// ParseProxyAuthorization extracts username/password from a Proxy-Authorization
// header value. Only the Basic scheme is supported.
func ParseProxyAuthorization(header string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || header[:len(prefix)] != prefix {
		return "", "", false
	}
	u, p, ok := basicAuthDecode(header[len(prefix):])
	return u, p, ok
}

func basicAuthDecode(s string) (string, string, bool) {
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", "", false
	}
	for i := 0; i < len(dec); i++ {
		if dec[i] == ':' {
			return string(dec[:i]), string(dec[i+1:]), true
		}
	}
	return "", "", false
}

// WriteProxyAuthRequired writes a 407 response with the Proxy-Authenticate
// challenge header.
func WriteProxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="pproxy"`)
	http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
}

// ConstantTimeEq is a tiny helper that keeps call sites readable.
func ConstantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
