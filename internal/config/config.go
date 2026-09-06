// Package config defines the YAML schema, loader, and hot-reload machinery
// for pproxy.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Protocol enumerates the listener and upstream proxy types we support.
type Protocol string

const (
	ProtocolHTTP   Protocol = "http"
	ProtocolHTTPS  Protocol = "https"
	ProtocolSOCKS5 Protocol = "socks5"
)

// Valid reports whether p is a recognised protocol identifier.
func (p Protocol) Valid() bool {
	switch p {
	case ProtocolHTTP, ProtocolHTTPS, ProtocolSOCKS5:
		return true
	}
	return false
}

// Config is the root schema of the YAML file.
type Config struct {
	Logging Logging    `yaml:"logging"`
	Server  Server     `yaml:"server"`
	Health  Health     `yaml:"health"`
	Auth    Auth       `yaml:"auth"`
	Listen  []Listen   `yaml:"listen"`
	Pool    []Upstream `yaml:"pool"`
}

// Logging controls the global slog/zap logger.
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Server holds process-wide runtime parameters.
type Server struct {
	MetricsAddress  string        `yaml:"metrics_address"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// Health holds the active health-check parameters.
type Health struct {
	Interval         time.Duration `yaml:"interval"`
	Timeout          time.Duration `yaml:"timeout"`
	FailThreshold    int           `yaml:"fail_threshold"`
	SuccessThreshold int           `yaml:"success_threshold"`
	// ProbeURL is the absolute URL used by HTTP probes. Defaults to
	// "http://example.com/" which most forward proxies accept without
	// rejecting for a scheme/port mismatch.
	ProbeURL string `yaml:"probe_url"`
	// ProbeHost is the host:port used by SOCKS5 connect probes. Defaults
	// to "example.com:80".
	ProbeHost string `yaml:"probe_host"`
}

// Auth holds the per-client credential store.
type Auth struct {
	Users []User `yaml:"users"`
}

// User is a single client credential. PasswordHash is a bcrypt-encoded value
// produced by tools outside the binary (e.g. htpasswd -bnBC 10 "" | tr -d ':\n').
type User struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// Listen describes a single inbound listener.
type Listen struct {
	Protocol Protocol `yaml:"protocol"`
	Address  string   `yaml:"address"`
	Port     int      `yaml:"port"`
}

// Upstream describes a single outbound proxy endpoint.
type Upstream struct {
	Name               string        `yaml:"name"`
	Type               Protocol      `yaml:"type"`
	Address            string        `yaml:"address"`
	Username           string        `yaml:"username"`
	Password           string        `yaml:"password"`
	TLS                bool          `yaml:"tls"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
	CAFile             string        `yaml:"ca_file"`
	DialTimeout        time.Duration `yaml:"dial_timeout"`
}

// Defaults returns a Config populated with the balanced defaults we ship.
func Defaults() Config {
	return Config{
		Logging: Logging{Level: "info", Format: "json"},
		Server: Server{
			MetricsAddress:  "0.0.0.0:9090",
			ShutdownTimeout: 30 * time.Second,
		},
		Health: Health{
			Interval:         15 * time.Second,
			Timeout:          5 * time.Second,
			FailThreshold:    2,
			SuccessThreshold: 2,
			ProbeURL:         "http://example.com/",
			ProbeHost:        "example.com:80",
		},
	}
}

// applyDefaults fills in zero-valued fields with the shipped defaults.
func (c *Config) applyDefaults() {
	d := Defaults()
	if c.Logging.Level == "" {
		c.Logging.Level = d.Logging.Level
	}
	if c.Logging.Format == "" {
		c.Logging.Format = d.Logging.Format
	}
	if c.Server.MetricsAddress == "" {
		c.Server.MetricsAddress = d.Server.MetricsAddress
	}
	if c.Server.ShutdownTimeout == 0 {
		c.Server.ShutdownTimeout = d.Server.ShutdownTimeout
	}
	if c.Health.Interval == 0 {
		c.Health.Interval = d.Health.Interval
	}
	if c.Health.Timeout == 0 {
		c.Health.Timeout = d.Health.Timeout
	}
	if c.Health.FailThreshold == 0 {
		c.Health.FailThreshold = d.Health.FailThreshold
	}
	if c.Health.SuccessThreshold == 0 {
		c.Health.SuccessThreshold = d.Health.SuccessThreshold
	}
	if c.Health.ProbeURL == "" {
		c.Health.ProbeURL = d.Health.ProbeURL
	}
	if c.Health.ProbeHost == "" {
		c.Health.ProbeHost = d.Health.ProbeHost
	}
	for i := range c.Listen {
		if c.Listen[i].Address == "" {
			c.Listen[i].Address = "0.0.0.0"
		}
	}
	for i := range c.Pool {
		if c.Pool[i].DialTimeout == 0 {
			c.Pool[i].DialTimeout = 10 * time.Second
		}
	}
}

// Load reads, parses, defaults, and validates the YAML at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}
