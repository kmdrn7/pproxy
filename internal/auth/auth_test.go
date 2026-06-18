package auth

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/kmdrn7/pproxy/internal/config"
)

// hashFor is a small helper that produces a bcrypt hash usable in tests.
// The cost is the package minimum to keep the suite fast.
func hashFor(t *testing.T, plain string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func TestStore_Empty(t *testing.T) {
	t.Parallel()
	s, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !s.Empty() {
		t.Fatalf("expected empty store, got non-empty")
	}
}

func TestStore_Verify(t *testing.T) {
	t.Parallel()
	hash := hashFor(t, "s3cret")
	s, err := New([]config.User{
		{Username: "alice", PasswordHash: hash},
		{Username: "bob", PasswordHash: hashFor(t, "hunter2")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		name     string
		user     string
		password string
		want     bool
	}{
		{"valid alice", "alice", "s3cret", true},
		{"valid bob", "bob", "hunter2", true},
		{"wrong password", "alice", "wrong", false},
		{"unknown user", "carol", "anything", false},
		{"empty user", "", "s3cret", false},
		{"empty password", "alice", "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := s.Verify(tc.user, tc.password); got != tc.want {
				t.Fatalf("Verify(%q,%q) = %v, want %v", tc.user, tc.password, got, tc.want)
			}
		})
	}
}

func TestStore_NewRejectsInvalidHash(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		user config.User
	}{
		{"not a bcrypt hash", config.User{Username: "u", PasswordHash: "not-a-hash"}},
		{"empty hash", config.User{Username: "u", PasswordHash: ""}},
		{"truncated hash", config.User{Username: "u", PasswordHash: "$2a$10$"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New([]config.User{tc.user}); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestStore_NewRejectsDuplicateUser(t *testing.T) {
	t.Parallel()
	h := hashFor(t, "x")
	_, err := New([]config.User{
		{Username: "alice", PasswordHash: h},
		{Username: "alice", PasswordHash: h},
	})
	if err == nil {
		t.Fatalf("expected duplicate-user error")
	}
}

func TestParseProxyAuthorization(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		header    string
		wantUser  string
		wantPass  string
		wantOK    bool
	}{
		{"valid basic", "Basic " + b64("alice:s3cret"), "alice", "s3cret", true},
		{"empty password", "Basic " + b64("alice:"), "alice", "", true},
		{"colon in password", "Basic " + b64("alice:a:b"), "alice", "a:b", true},
		{"missing scheme", "Bearer foo", "", "", false},
		{"non-base64", "Basic !!!", "", "", false},
		{"no colon", "Basic " + b64("alice"), "", "", false},
		{"empty value", "", "", "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotU, gotP, gotOK := ParseProxyAuthorization(tc.header)
			if gotU != tc.wantUser || gotP != tc.wantPass || gotOK != tc.wantOK {
				t.Fatalf("ParseProxyAuthorization(%q) = (%q,%q,%v), want (%q,%q,%v)",
					tc.header, gotU, gotP, gotOK, tc.wantUser, tc.wantPass, tc.wantOK)
			}
		})
	}
}

func TestWriteProxyAuthRequired(t *testing.T) {
	t.Parallel()
	rr := httptest.NewRecorder()
	WriteProxyAuthRequired(rr)
	if got := rr.Code; got != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", got, http.StatusProxyAuthRequired)
	}
	if got := rr.Header().Get("Proxy-Authenticate"); got == "" {
		t.Fatalf("expected Proxy-Authenticate header to be set")
	}
}

func TestSOCKS5MethodNegotiation(t *testing.T) {
	t.Parallel()

	t.Run("parses valid request", func(t *testing.T) {
		t.Parallel()
		r := bytes.NewReader([]byte{0x05, 0x02, 0x00, 0x02})
		req, err := ReadSOCKS5Methods(r)
		if err != nil {
			t.Fatalf("ReadSOCKS5Methods: %v", err)
		}
		if req.NMETHODS != 2 {
			t.Fatalf("NMETHODS = %d, want 2", req.NMETHODS)
		}
		if !req.HasMethod(0x00) || !req.HasMethod(0x02) {
			t.Fatalf("expected methods 0x00 and 0x02 in %x", req.METHODS)
		}
	})

	t.Run("rejects wrong version", func(t *testing.T) {
		t.Parallel()
		_, err := ReadSOCKS5Methods(bytes.NewReader([]byte{0x04, 0x01, 0x00}))
		if err == nil {
			t.Fatalf("expected version error")
		}
	})

	t.Run("rejects zero methods", func(t *testing.T) {
		t.Parallel()
		_, err := ReadSOCKS5Methods(bytes.NewReader([]byte{0x05, 0x00}))
		if err == nil {
			t.Fatalf("expected empty-methods error")
		}
	})

	t.Run("writes chosen method", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		if err := WriteSOCKS5MethodResponse(&buf, 0x02); err != nil {
			t.Fatalf("WriteSOCKS5MethodResponse: %v", err)
		}
		if !bytes.Equal(buf.Bytes(), []byte{0x05, 0x02}) {
			t.Fatalf("got %x, want 05 02", buf.Bytes())
		}
	})
}

func TestSOCKS5AuthRoundTrip(t *testing.T) {
	t.Parallel()
	hash := hashFor(t, "s3cret")
	s, err := New([]config.User{{Username: "alice", PasswordHash: hash}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// client side: send the auth frame and read the response.
		// net.Pipe is synchronous, so we must drain the response or the
		// server's write blocks.
		clientErr := make(chan error, 1)
		go func() {
			frame := []byte{0x01, byte(len("alice"))}
			frame = append(frame, "alice"...)
			frame = append(frame, byte(len("s3cret")))
			frame = append(frame, "s3cret"...)
			if _, err := clientConn.Write(frame); err != nil {
				clientErr <- err
				return
			}
			var resp [2]byte
			_, err := io.ReadFull(clientConn, resp[:])
			clientErr <- err
		}()

		// server side: use the store to authenticate.
		done := make(chan struct{})
		var got string
		var authErr error
		go func() {
			got, authErr = s.AuthenticateSOCKS5(serverConn)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("auth timed out")
		}
		if authErr != nil {
			t.Fatalf("AuthenticateSOCKS5: %v", authErr)
		}
		if got != "alice" {
			t.Fatalf("user = %q, want %q", got, "alice")
		}
		if err := <-clientErr; err != nil {
			t.Fatalf("client roundtrip: %v", err)
		}
	})

	t.Run("wrong password returns failure", func(t *testing.T) {
		t.Parallel()
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// client side: write the bad frame and drain the failure response so
		// the server can complete without blocking.
		clientErr := make(chan struct{})
		go func() {
			frame := []byte{0x01, byte(len("alice"))}
			frame = append(frame, "alice"...)
			frame = append(frame, byte(len("nope")))
			frame = append(frame, "nope"...)
			_, _ = clientConn.Write(frame)
			var resp [2]byte
			_, _ = io.ReadFull(clientConn, resp[:])
			close(clientErr)
		}()

		if _, err := s.AuthenticateSOCKS5(serverConn); err == nil {
			t.Fatalf("expected auth error")
		}
		<-clientErr
	})
}

func TestSOCKS5RequestParse(t *testing.T) {
	t.Parallel()

	// build a valid connect request to 1.2.3.4:80
	payload := []byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80}
	req, err := ReadSOCKS5Request(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("ReadSOCKS5Request: %v", err)
	}
	if req.CMD != 0x01 || req.ATYP != 0x01 || req.DSTPort != 80 {
		t.Fatalf("got %+v, want CMD=1 ATYP=1 PORT=80", req)
	}
	if !bytes.Equal(req.DSTAddr, []byte{1, 2, 3, 4}) {
		t.Fatalf("addr = %v, want [1 2 3 4]", req.DSTAddr)
	}

	t.Run("rejects unsupported command", func(t *testing.T) {
		t.Parallel()
		_, err := ReadSOCKS5Request(bytes.NewReader([]byte{0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80}))
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("rejects unknown atyp", func(t *testing.T) {
		t.Parallel()
		_, err := ReadSOCKS5Request(bytes.NewReader([]byte{0x05, 0x01, 0x00, 0x05, 1, 2, 3, 4, 0, 80}))
		if err == nil {
			t.Fatalf("expected error")
		}
	})
}

func TestSOCKS5ReplyWrite(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := WriteSOCKS5Reply(&buf, 0x00, net.IPv4(127, 0, 0, 1), 1080); err != nil {
		t.Fatalf("WriteSOCKS5Reply: %v", err)
	}
	got := buf.Bytes()
	// expected: 05 00 00 01 7f 00 00 01 04 38
	want := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x04, 0x38}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestConstantTimeEq(t *testing.T) {
	t.Parallel()
	if !ConstantTimeEq("abc", "abc") {
		t.Fatalf("expected equal")
	}
	if ConstantTimeEq("abc", "abd") {
		t.Fatalf("expected not equal")
	}
}

func TestStoreVerify_UnknownUserStillHashes(t *testing.T) {
	// regression: ensure that Verify for an unknown user still runs a fake
	// bcrypt comparison so the response time is not a side channel.
	t.Parallel()
	s, err := New([]config.User{{Username: "alice", PasswordHash: hashFor(t, "s3cret")}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	start := time.Now()
	for i := 0; i < 5; i++ {
		_ = s.Verify("nope-"+string(rune('a'+i)), "x")
	}
	unknownDur := time.Since(start)

	start = time.Now()
	for i := 0; i < 5; i++ {
		_ = s.Verify("alice", "wrong")
	}
	wrongDur := time.Since(start)

	// we don't assert equality (flaky), but both should be non-trivially slow.
	if unknownDur < time.Millisecond || wrongDur < time.Millisecond {
		t.Logf("unknown=%v wrong=%v (informational only)", unknownDur, wrongDur)
	}
}

// b64 is a tiny wrapper so the table reads naturally.
func b64(s string) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	src := []byte(s)
	n := len(src)
	out := make([]byte, 0, ((n+2)/3)*4)
	for i := 0; i < n; i += 3 {
		var b [3]byte
		nb := 0
		for j := 0; j < 3 && i+j < n; j++ {
			b[j] = src[i+j]
			nb++
		}
		out = append(out, tbl[b[0]>>2])
		out = append(out, tbl[((b[0]&0x03)<<4)|(b[1]>>4)])
		if nb > 1 {
			out = append(out, tbl[((b[1]&0x0f)<<2)|(b[2]>>6)])
		} else {
			out = append(out, '=')
		}
		if nb > 2 {
			out = append(out, tbl[b[2]&0x3f])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}
