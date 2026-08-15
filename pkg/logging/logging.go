package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync/atomic"
)

// Both are read from every logging goroutine while SetLogger / SetDebug
// may replace them concurrently (the Caddy plugin swaps the logger on
// config reload), so they are accessed atomically.
var (
	debugEnabled atomic.Bool
	logger       atomic.Pointer[log.Logger]
)

func init() {
	logger.Store(log.New(os.Stderr, "", log.LstdFlags))
}

// currentLogger returns the active logger, never nil.
func currentLogger() *log.Logger {
	if l := logger.Load(); l != nil {
		return l
	}
	return log.New(os.Stderr, "", log.LstdFlags)
}

// SetLogFile adds a log file as an additional output alongside stderr.
func SetLogFile(logFilePath string) {
	if logFilePath == "" {
		return
	}
	logFile, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		Error("Failed to open log file path: %s, error: %s", logFilePath, err)
		return
	}
	Info("Log to file path: %s", logFilePath)
	currentLogger().SetOutput(io.MultiWriter(os.Stderr, logFile))
}

// SetLogger replaces the underlying logger instance. Used by the Caddy
// integration to route output through Caddy's zap logger. A nil logger
// is ignored so in-flight logging never panics.
func SetLogger(l *log.Logger) {
	if l == nil {
		return
	}
	logger.Store(l)
}

func SetDebug(enabled bool) {
	debugEnabled.Store(enabled)
}

func logf(prefix, format string, v ...any) {
	currentLogger().Printf("%s %s", prefix, fmt.Sprintf(format, v...))
}

func Debug(format string, v ...any) {
	if debugEnabled.Load() {
		logf("[DEB]", format, v...)
	}
}

func Info(format string, v ...any)   { logf("[INF]", format, v...) }
func Notice(format string, v ...any) { logf("[NOT]", format, v...) }
func Warn(format string, v ...any)   { logf("[WRN]", format, v...) }
func Error(format string, v ...any)  { logf("[ERR]", format, v...) }

func Fatal(format string, v ...any) {
	currentLogger().Fatalf("[ERR] %s", fmt.Sprintf(format, v...))
}

// ---------------------------------------------------------------------------
// Adapters for external loggers (net/http, lego ACME)
// ---------------------------------------------------------------------------

// warnWriter is an io.Writer that routes each written line through Warn().
type warnWriter struct{}

func (warnWriter) Write(p []byte) (int, error) {
	s := strings.TrimRight(string(p), "\n")
	if s != "" {
		Warn("%s", s)
	}
	return len(p), nil
}

// ErrorLogger returns a *log.Logger suitable for http.Server.ErrorLog.
// Every line written to it is emitted with the [WRN] prefix.
func ErrorLogger() *log.Logger {
	return log.New(warnWriter{}, "", 0)
}

// LegoLogger satisfies lego's log.StdLogger interface and routes messages
// through the certdx logging functions, translating lego prefixes:
//
//	[INFO] → [INF]
//	[WARN] → [WRN]
//	Fatal  → [ERR] (via Fatal)
type LegoLogger struct{}

func (LegoLogger) Printf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	switch {
	case strings.HasPrefix(msg, "[INFO] "):
		Info("%s", strings.TrimPrefix(msg, "[INFO] "))
	case strings.HasPrefix(msg, "[WARN] "):
		Warn("%s", strings.TrimPrefix(msg, "[WARN] "))
	default:
		Info("%s", msg)
	}
}

func (LegoLogger) Print(args ...any)                 { Info("%s", fmt.Sprint(args...)) }
func (LegoLogger) Println(args ...any)               { Info("%s", fmt.Sprint(args...)) }
func (LegoLogger) Fatal(args ...any)                 { Fatal("%s", fmt.Sprint(args...)) }
func (LegoLogger) Fatalln(args ...any)               { Fatal("%s", fmt.Sprint(args...)) }
func (LegoLogger) Fatalf(format string, args ...any) { Fatal(format, args...) }
