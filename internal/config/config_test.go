package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtocolValid(t *testing.T) {
	t.Parallel()
	for _, p := range []Protocol{ProtocolHTTP, ProtocolHTTPS, ProtocolSOCKS5} {
		if !p.Valid() {
			t.Errorf("expected %q to be valid", p)
		}
	}
	for _, p := range []Protocol{"", "ftp", "SOCKS5", "socks"} {
		if p.Valid() {
			t.Errorf("expected %q to be invalid", p)
		}
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	d := Defaults()
	if d.Logging.Level == "" || d.Logging.Format == "" {
		t.Fatalf("logging defaults empty: %+v", d.Logging)
	}
	if d.Health.Interval <= 0 || d.Health.Timeout <= 0 {
		t.Fatalf("health defaults not positive: %+v", d.Health)
	}
	if d.Server.ShutdownTimeout <= 0 {
		t.Fatalf("server shutdown timeout not positive")
	}
}

func TestLoad_AppliesDefaults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	minimal := `
listen:
  - protocol: http
    port: 8080
pool:
  - name: u1
    type: http
    address: 1.2.3.4:3128
`
	if err := os.WriteFile(path, []byte(minimal), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Health.Interval == 0 {
		t.Errorf("health interval not defaulted")
	}
	if c.Logging.Level == "" {
		t.Errorf("logging level not defaulted")
	}
	if c.Listen[0].Address != "0.0.0.0" {
		t.Errorf("listener address not defaulted, got %q", c.Listen[0].Address)
	}
}

func TestLoad_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	contents := `
unknown_field: true
listen:
  - protocol: http
    port: 8080
pool:
  - name: u1
    type: http
    address: 1.2.3.4:3128
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected unknown-field error")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("listen: [unclosed"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected parse error")
	}
}
