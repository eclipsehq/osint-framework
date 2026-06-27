package logger

import (
	"log/slog"
	"os"
)

func Init(level, format string) *slog.Logger {
	var opts slog.HandlerOptions
	switch level {
	case "debug":
		opts.Level = slog.LevelDebug
	case "info":
		opts.Level = slog.LevelInfo
	case "warn", "warning":
		opts.Level = slog.LevelWarn
	case "error":
		opts.Level = slog.LevelError
	default:
		opts.Level = slog.LevelInfo
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, &opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, &opts)
	}

	return slog.New(handler)
}
