package auth

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kmdrn7/pproxy/internal/config"
)

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
