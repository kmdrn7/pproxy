package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/kmdrn7/pproxy/internal/config"
)

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
