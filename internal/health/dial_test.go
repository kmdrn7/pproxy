package health

import "testing"

func TestHostnameOf(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"1.2.3.4:80", "1.2.3.4"},
		{"[::1]:1080", "::1"},
		{"example.com:443", "example.com"},
		{"no-port", "no-port"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := hostnameOf(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoadCAPool(t *testing.T) {
	t.Parallel()
	t.Run("empty path returns nil pool", func(t *testing.T) {
		t.Parallel()
		p, err := loadCAPool("")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if p != nil {
			t.Fatalf("expected nil, got %+v", p)
		}
	})
	t.Run("missing file errors", func(t *testing.T) {
		t.Parallel()
		if _, err := loadCAPool("/nonexistent/ca.pem"); err == nil {
			t.Fatalf("expected error for missing file")
		}
	})
	t.Run("garbage pem errors", func(t *testing.T) {
		t.Parallel()
		if _, err := loadCAPool("/dev/null"); err == nil {
			t.Fatalf("expected error for empty pem")
		}
	})
}
