package health

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/kmdrn7/pproxy/internal/config"
)

func TestParsePort(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"80", 80, false},
		{"1", 1, false},
		{"65535", 65535, false},
		{"0", 0, true},
		{"65536", 0, true},
		{"abc", 0, true},
		{"", 0, true},
		{"-1", 0, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := parsePort(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestProbeSOCKS5_Rejects(t *testing.T) {
	t.Parallel()
	s := newTestScheduler(t)
	t.Run("unreachable upstream", func(t *testing.T) {
		t.Parallel()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.probeSOCKS5(ctx, config.Upstream{Address: addr, DialTimeout: 500 * time.Millisecond}); err == nil {
			t.Fatalf("expected error for unreachable upstream")
		}
	})
}
