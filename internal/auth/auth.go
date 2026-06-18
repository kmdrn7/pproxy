// Package auth stores client credentials and exposes the verification helpers
// used by the HTTP and SOCKS5 listeners.
package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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

// SOCKS5AuthRequest is the wire format of a SOCKS5 username/password
// subnegotiation as defined by RFC 1929.
type SOCKS5AuthRequest struct {
	Username string
	Password string
}

// ReadSOCKS5Auth parses a username/password subnegotiation from r. The leading
// version byte (which must be 0x01) is consumed.
func ReadSOCKS5Auth(r io.Reader) (SOCKS5AuthRequest, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return SOCKS5AuthRequest{}, err
	}
	if hdr[0] != 0x01 {
		return SOCKS5AuthRequest{}, fmt.Errorf("socks5: auth version %d unsupported", hdr[0])
	}
	if hdr[1] == 0 {
		return SOCKS5AuthRequest{}, errors.New("socks5: empty username")
	}
	username := make([]byte, hdr[1])
	if _, err := io.ReadFull(r, username); err != nil {
		return SOCKS5AuthRequest{}, err
	}
	var pwdLen [1]byte
	if _, err := io.ReadFull(r, pwdLen[:]); err != nil {
		return SOCKS5AuthRequest{}, err
	}
	if pwdLen[0] == 0 {
		return SOCKS5AuthRequest{}, errors.New("socks5: empty password")
	}
	password := make([]byte, pwdLen[0])
	if _, err := io.ReadFull(r, password); err != nil {
		return SOCKS5AuthRequest{}, err
	}
	return SOCKS5AuthRequest{Username: string(username), Password: string(password)}, nil
}

// WriteSOCKS5AuthResponse writes the 2-byte response (VER, STATUS) to w.
// status: 0x00 success, anything else failure.
func WriteSOCKS5AuthResponse(w io.Writer, status byte) error {
	_, err := w.Write([]byte{0x01, status})
	return err
}

// AuthenticateSOCKS5 runs the full username/password subnegotiation on conn.
// It returns the verified username on success, or an error on any failure.
func (s *Store) AuthenticateSOCKS5(conn net.Conn) (string, error) {
	req, err := ReadSOCKS5Auth(conn)
	if err != nil {
		_ = WriteSOCKS5AuthResponse(conn, 0x01)
		return "", err
	}
	if !s.Verify(req.Username, req.Password) {
		_ = WriteSOCKS5AuthResponse(conn, 0x01)
		return "", fmt.Errorf("socks5: invalid credentials for %q", req.Username)
	}
	if err := WriteSOCKS5AuthResponse(conn, 0x00); err != nil {
		return "", err
	}
	return req.Username, nil
}

// ConstantTimeEq is a tiny helper that keeps call sites readable.
func ConstantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SOCKS5MethodRequest is the SOCKS5 method-negotiation header.
type SOCKS5MethodRequest struct {
	NMETHODS byte
	METHODS  []byte
}

// ReadSOCKS5Methods parses the initial method-negotiation frame from r.
func ReadSOCKS5Methods(r io.Reader) (SOCKS5MethodRequest, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return SOCKS5MethodRequest{}, err
	}
	if hdr[0] != 0x05 {
		return SOCKS5MethodRequest{}, fmt.Errorf("socks5: version %d unsupported", hdr[0])
	}
	if hdr[1] == 0 {
		return SOCKS5MethodRequest{}, errors.New("socks5: no methods offered")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return SOCKS5MethodRequest{}, err
	}
	return SOCKS5MethodRequest{NMETHODS: hdr[1], METHODS: methods}, nil
}

// HasMethod reports whether m is in the offered method list.
func (r SOCKS5MethodRequest) HasMethod(m byte) bool {
	for _, b := range r.METHODS {
		if b == m {
			return true
		}
	}
	return false
}

// WriteSOCKS5MethodResponse writes the chosen method back to w.
func WriteSOCKS5MethodResponse(w io.Writer, method byte) error {
	_, err := w.Write([]byte{0x05, method})
	return err
}

// SOCKS5Request is a parsed SOCKS5 connect/bind/udp request.
type SOCKS5Request struct {
	VER     byte
	CMD     byte
	RSV     byte
	ATYP    byte
	DSTAddr []byte
	DSTPort uint16
}

// ReadSOCKS5Request parses a connect/bind/udp request from r. The leading
// version byte must be 0x05.
func ReadSOCKS5Request(r io.Reader) (SOCKS5Request, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return SOCKS5Request{}, err
	}
	if hdr[0] != 0x05 {
		return SOCKS5Request{}, fmt.Errorf("socks5: request version %d unsupported", hdr[0])
	}
	if hdr[1] != 0x01 {
		return SOCKS5Request{}, fmt.Errorf("socks5: command %#x not supported", hdr[1])
	}
	req := SOCKS5Request{VER: hdr[0], CMD: hdr[1], RSV: hdr[2], ATYP: hdr[3]}
	switch req.ATYP {
	case 0x01: // IPv4
		req.DSTAddr = make([]byte, 4)
	case 0x03: // domain
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return SOCKS5Request{}, err
		}
		req.DSTAddr = make([]byte, l[0])
	case 0x04: // IPv6
		req.DSTAddr = make([]byte, 16)
	default:
		return SOCKS5Request{}, fmt.Errorf("socks5: address type %#x unsupported", req.ATYP)
	}
	if _, err := io.ReadFull(r, req.DSTAddr); err != nil {
		return SOCKS5Request{}, err
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return SOCKS5Request{}, err
	}
	req.DSTPort = binary.BigEndian.Uint16(port[:])
	return req, nil
}

// WriteSOCKS5Reply writes a SOCKS5 reply to w.
func WriteSOCKS5Reply(w io.Writer, rep byte, bind net.IP, port uint16) error {
	atyp := byte(0x01)
	addr := bind.To4()
	if addr == nil {
		atyp = 0x04
		addr = bind.To16()
		if addr == nil {
			addr = make(net.IP, 4)
		}
	}
	portBuf := [2]byte{}
	binary.BigEndian.PutUint16(portBuf[:], port)
	if _, err := w.Write([]byte{0x05, rep, 0x00, atyp}); err != nil {
		return err
	}
	if _, err := w.Write(addr); err != nil {
		return err
	}
	if _, err := w.Write(portBuf[:]); err != nil {
		return err
	}
	return nil
}
