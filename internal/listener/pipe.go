package listener

import (
	"io"
	"log/slog"
	"net"
)

// pump copies bytes in both directions between client and upstream,
// closing the connection when either side returns an error.
func pump(client, upstream net.Conn, proto, upstreamName string, log *slog.Logger) {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, client)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(client, upstream)
		errCh <- err
	}()
	<-errCh
	_ = client.Close()
	_ = upstream.Close()
}
