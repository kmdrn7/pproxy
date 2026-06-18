// Package logger provides a process-wide slog.Logger backed by zap.
package logger

import (
	"log/slog"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
)

// Options configures the global logger.
type Options struct {
	Level  string // debug, info, warn, error
	Format string // json, text
}

// New builds a *slog.Logger using zap as the backend. The returned logger
// emits records at the configured level in JSON or text format.
func New(opts Options) *slog.Logger {
	level := parseLevel(opts.Level)
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.RFC3339NanoTimeEncoder

	var core zapcore.Core
	switch strings.ToLower(opts.Format) {
	case "text", "console":
		core = zapcore.NewCore(zapcore.NewConsoleEncoder(encCfg), zapcore.AddSync(os.Stdout), level)
	default:
		core = zapcore.NewCore(zapcore.NewJSONEncoder(encCfg), zapcore.AddSync(os.Stdout), level)
	}

	return slog.New(zapslog.NewHandler(core, zapslog.WithCaller(true)))
}

func parseLevel(s string) zapcore.Level {
	switch strings.ToLower(s) {
	case "debug":
		return zapcore.DebugLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}
