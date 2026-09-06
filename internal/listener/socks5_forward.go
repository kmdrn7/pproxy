package listener

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/kmdrn7/pproxy/internal/auth"
	"github.com/kmdrn7/pproxy/internal/config"
)

func (l *SOCKS5Listener) tryForward(clientConn net.Conn, req auth.SOCKS5Request, ups config.Upstream) bool {
	dialTimeout := ups.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	upstreamConn, err := dialUpstream(ctx, ups)
	if err != nil {
		l.deps.Log.Debug("socks5: dial upstream", "upstream", ups.Name, "err", err)
		return false
	}
	defer upstreamConn.Close()

	// Method negotiation with the upstream. Always required; only the
	// offered method depends on whether credentials are configured.
	offered := byte(0x00)
	if ups.Username != "" {
		offered = 0x02
	}
	if _, err := upstreamConn.Write([]byte{0x05, 0x01, offered}); err != nil {
		return false
	}
	var sel [2]byte
	if _, err := io.ReadFull(upstreamConn, sel[:]); err != nil {
		return false
	}
	if sel[0] != 0x05 || sel[1] != offered {
		return false
	}
	if offered == 0x02 {
		if err := socks5UpstreamAuthSubmit(upstreamConn, ups.Username, ups.Password); err != nil {
			l.deps.Log.Debug("socks5: upstream auth", "upstream", ups.Name, "err", err)
			return false
		}
	}

	if err := writeSOCKS5Request(upstreamConn, req); err != nil {
		return false
	}
	rep, err := readSOCKS5ReplyFrame(bufio.NewReader(upstreamConn))
	if err != nil {
		return false
	}
	if rep != 0x00 {
		return false
	}
	if err := auth.WriteSOCKS5Reply(clientConn, 0x00, net.IPv4zero, 0); err != nil {
		return false
	}
	pump(clientConn, upstreamConn, string(l.proto), ups.Name, l.deps.Log)
	return true
}

// socks5UpstreamAuthSubmit sends a username/password subnegotiation frame
// to the upstream and verifies the success response.
func socks5UpstreamAuthSubmit(conn net.Conn, user, pass string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x05 || hdr[1] != 0x02 {
		return fmt.Errorf("socks5: upstream refused auth method: %#x", hdr[1])
	}
	u := []byte(user)
	p := []byte(pass)
	frame := []byte{0x01, byte(len(u))}
	frame = append(frame, u...)
	frame = append(frame, byte(len(p)))
	frame = append(frame, p...)
	if _, err := conn.Write(frame); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("socks5: upstream rejected credentials")
	}
	return nil
}

// writeSOCKS5Request serialises req onto w, preserving the original ATYP
// and DST fields so the upstream sees an exact copy of the client's request.
func writeSOCKS5Request(w io.Writer, req auth.SOCKS5Request) error {
	buf := []byte{req.VER, req.CMD, req.RSV, req.ATYP}
	if req.ATYP == 0x03 {
		buf = append(buf, byte(len(req.DSTAddr)))
	}
	buf = append(buf, req.DSTAddr...)
	port := [2]byte{byte(req.DSTPort >> 8), byte(req.DSTPort & 0xff)}
	buf = append(buf, port[:]...)
	_, err := w.Write(buf)
	return err
}

// readSOCKS5ReplyFrame consumes the first reply from r and returns its REP
// byte. BND.ADDR and BND.PORT are read but discarded because we surface only
// success/failure to the client.
func readSOCKS5ReplyFrame(r *bufio.Reader) (byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] != 0x05 {
		return 0, fmt.Errorf("socks5: reply version %#x", hdr[0])
	}
	var addrLen int
	switch hdr[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return 0, err
		}
		addrLen = int(l[0])
	default:
		return 0, fmt.Errorf("socks5: reply atyp %#x", hdr[3])
	}
	if addrLen > 0 {
		if _, err := io.Copy(io.Discard, io.LimitReader(r, int64(addrLen))); err != nil {
			return 0, err
		}
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(r, 2)); err != nil { // port
		return 0, err
	}
	return hdr[1], nil
}
