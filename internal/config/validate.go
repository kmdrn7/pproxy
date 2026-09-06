package config

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

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
