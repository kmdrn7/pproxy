package config

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher fires onChange whenever the config file at path is modified on
// disk. It also exposes a Trigger channel that callers can signal (e.g. on
// SIGHUP) to force an immediate reload.
type Watcher struct {
	path     string
	log      *slog.Logger
	onChange func(*Config)
}

// NewWatcher returns a Watcher bound to path. The callback runs synchronously
// on the watcher's goroutine; the caller is responsible for re-entrancy.
func NewWatcher(path string, log *slog.Logger, onChange func(*Config)) *Watcher {
	return &Watcher{path: path, log: log, onChange: onChange}
}

// Run blocks until ctx is cancelled, reloading on fsnotify events and on
// values from trigger. It debounces bursts and re-adds the watch after a
// rename, since editors swap files via rename(2), which orphans the
// inotify watch on the old inode.
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
