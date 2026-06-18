// Package config defines the YAML schema, loader, and hot-reload machinery
// for pproxy.
package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
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
	Logging Logging `yaml:"logging"`
	Server  Server  `yaml:"server"`
	Health  Health  `yaml:"health"`
	Auth    Auth    `yaml:"auth"`
	Listen  []Listen `yaml:"listen"`
	Pool    []Upstream `yaml:"pool"`
}

// Logging controls the global slog/zap logger.
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Server holds process-wide runtime parameters.
type Server struct {
	MetricsAddress string        `yaml:"metrics_address"`
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

// Validate enforces the invariants the rest of the binary relies on.
func (c *Config) Validate() error {
	if len(c.Listen) == 0 {
		return errors.New("config: at least one listen entry is required")
	}
	if len(c.Pool) == 0 {
		return errors.New("config: at least one pool entry is required")
	}
	listenKeys := make(map[string]struct{}, len(c.Listen))
	for i, l := range c.Listen {
		if !l.Protocol.Valid() {
			return fmt.Errorf("config: listen[%d]: invalid protocol %q", i, l.Protocol)
		}
		if l.Port <= 0 || l.Port > 65535 {
			return fmt.Errorf("config: listen[%d]: port must be 1..65535", i)
		}
		k := fmt.Sprintf("%s|%s:%d", l.Protocol, l.Address, l.Port)
		if _, dup := listenKeys[k]; dup {
			return fmt.Errorf("config: listen[%d]: duplicate listener %s", i, k)
		}
		listenKeys[k] = struct{}{}
	}
	poolNames := make(map[string]struct{}, len(c.Pool))
	for i, u := range c.Pool {
		if strings.TrimSpace(u.Name) == "" {
			return fmt.Errorf("config: pool[%d]: name is required", i)
		}
		if _, dup := poolNames[u.Name]; dup {
			return fmt.Errorf("config: pool[%d]: duplicate name %q", i, u.Name)
		}
		poolNames[u.Name] = struct{}{}
		if !u.Type.Valid() {
			return fmt.Errorf("config: pool[%d] %q: invalid type %q", i, u.Name, u.Type)
		}
		if u.Address == "" {
			return fmt.Errorf("config: pool[%d] %q: address is required", i, u.Name)
		}
	}
	if c.Health.Interval < time.Second {
		return errors.New("config: health.interval must be >= 1s")
	}
	if c.Health.Timeout >= c.Health.Interval {
		return errors.New("config: health.timeout must be less than health.interval")
	}
	if c.Health.FailThreshold < 1 {
		return errors.New("config: health.fail_threshold must be >= 1")
	}
	if c.Health.SuccessThreshold < 1 {
		return errors.New("config: health.success_threshold must be >= 1")
	}
	if c.Server.ShutdownTimeout < time.Second {
		return errors.New("config: server.shutdown_timeout must be >= 1s")
	}
	seen := make(map[string]struct{}, len(c.Auth.Users))
	for i, u := range c.Auth.Users {
		if u.Username == "" {
			return fmt.Errorf("config: auth.users[%d]: username is required", i)
		}
		if u.PasswordHash == "" {
			return fmt.Errorf("config: auth.users[%d] %q: password_hash is required", i, u.Username)
		}
		if _, dup := seen[u.Username]; dup {
			return fmt.Errorf("config: auth.users[%d]: duplicate username %q", i, u.Username)
		}
		seen[u.Username] = struct{}{}
	}
	return nil
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

// Watcher fires onChange whenever the config file at path is modified on
// disk. It also exposes a Trigger channel that callers can signal (e.g. on
// SIGHUP) to force an immediate reload.
type Watcher struct {
	path    string
	log     *slog.Logger
	onChange func(*Config)
}

// NewWatcher returns a Watcher bound to path. The callback runs synchronously
// on the watcher's goroutine; the caller is responsible for re-entrancy.
func NewWatcher(path string, log *slog.Logger, onChange func(*Config)) *Watcher {
	return &Watcher{path: path, log: log, onChange: onChange}
}

// Run blocks until ctx is cancelled, reloading the config on fsnotify events
// and on every value received from trigger. If a reload fails the error is
// logged and the previous config is kept. The initial config is the
// caller's responsibility; this watcher only handles subsequent updates.
//
// The watcher debounces bursts (a single editor save typically produces
// several fsnotify events: CREATE for the temp file, WRITE for the
// contents, RENAME for the swap-in) and re-installs the watch after a
// RENAME because the inotify watch is bound to the old inode.
func (w *Watcher) Run(ctx context.Context, trigger <-chan struct{}) error {
	dir := filepath.Dir(w.path)
	const debounce = 200 * time.Millisecond

	fs, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("config: watch: %w", err)
	}
	defer fs.Close()

	if err := fs.Add(dir); err != nil {
		return fmt.Errorf("config: watch dir %s: %w", dir, err)
	}

	var debounceTimer *time.Timer
	scheduleReload := func(reason string) {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		debounceTimer = time.AfterFunc(debounce, func() {
			w.reload(reason)
		})
	}

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return nil
		case ev, ok := <-fs.Events:
			if !ok {
				return nil
			}
			// Some editors swap the file via rename(2); the inotify watch
			// on the old inode is no longer valid. Re-add the watch so we
			// keep receiving events on the new inode.
			if ev.Op&fsnotify.Rename != 0 {
				if err := fs.Add(dir); err != nil {
					w.log.Error("config: re-add watch after rename failed", "err", err)
				}
			}
			if filepath.Clean(ev.Name) != filepath.Clean(w.path) {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				scheduleReload("fsnotify")
			}
		case err, ok := <-fs.Errors:
			if !ok {
				return nil
			}
			w.log.Error("config: fsnotify error", "err", err)
		case <-trigger:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			w.reload("signal")
		}
	}
}

func (w *Watcher) reload(reason string) {
	cfg, err := Load(w.path)
	if err != nil {
		w.log.Error("config: reload failed", "reason", reason, "err", err)
		return
	}
	w.log.Info("config: reloaded", "reason", reason, "upstreams", len(cfg.Pool), "listeners", len(cfg.Listen))
	w.onChange(cfg)
}
