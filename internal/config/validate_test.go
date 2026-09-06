package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	validUpstream := Upstream{Name: "u1", Type: ProtocolHTTP, Address: "1.2.3.4:3128"}
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "ok",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
			},
		},
		{
			name:    "missing listen",
			mutate:  func(c *Config) {},
			wantErr: "listen",
		},
		{
			name: "missing pool",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
			},
			wantErr: "pool",
		},
		{
			name: "invalid listen protocol",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: "ftp", Port: 8080}}
				c.Pool = []Upstream{validUpstream}
			},
			wantErr: "protocol",
		},
		{
			name: "invalid listen port",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 0}}
				c.Pool = []Upstream{validUpstream}
			},
			wantErr: "port",
		},
		{
			name: "duplicate listen",
			mutate: func(c *Config) {
				c.Listen = []Listen{
					{Protocol: ProtocolHTTP, Address: "0.0.0.0", Port: 8080},
					{Protocol: ProtocolHTTP, Address: "0.0.0.0", Port: 8080},
				}
				c.Pool = []Upstream{validUpstream}
			},
			wantErr: "duplicate listener",
		},
		{
			name: "duplicate pool name",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{
					{Name: "u1", Type: ProtocolHTTP, Address: "1.2.3.4:3128"},
					{Name: "u1", Type: ProtocolHTTP, Address: "5.6.7.8:3128"},
				}
			},
			wantErr: "duplicate name",
		},
		{
			name: "upstream without name",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{{Type: ProtocolHTTP, Address: "1.2.3.4:3128"}}
			},
			wantErr: "name is required",
		},
		{
			name: "upstream invalid type",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{{Name: "u", Type: "ftp", Address: "1.2.3.4:3128"}}
			},
			wantErr: "invalid type",
		},
		{
			name: "upstream without address",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{{Name: "u", Type: ProtocolHTTP}}
			},
			wantErr: "address is required",
		},
		{
			name: "health interval too small",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Health.Interval = 100 * time.Millisecond
			},
			wantErr: "health.interval",
		},
		{
			name: "health timeout not less than interval",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Health.Interval = 5 * time.Second
				c.Health.Timeout = 10 * time.Second
			},
			wantErr: "health.timeout",
		},
		{
			name: "auth user without username",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Auth.Users = []User{{PasswordHash: "x"}}
			},
			wantErr: "username is required",
		},
		{
			name: "auth user without hash",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Auth.Users = []User{{Username: "u"}}
			},
			wantErr: "password_hash is required",
		},
		{
			name: "auth duplicate username",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Auth.Users = []User{
					{Username: "u", PasswordHash: "x"},
					{Username: "u", PasswordHash: "x"},
				}
			},
			wantErr: "duplicate username",
		},
		{
			name: "shutdown timeout too small",
			mutate: func(c *Config) {
				c.Listen = []Listen{{Protocol: ProtocolHTTP, Port: 8080}}
				c.Pool = []Upstream{validUpstream}
				c.Server.ShutdownTimeout = 50 * time.Millisecond
			},
			wantErr: "shutdown_timeout",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Defaults()
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
