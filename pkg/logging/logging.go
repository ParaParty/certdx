package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var (
	debugEnabled bool
	logger       = log.New(os.Stderr, "", log.LstdFlags)
)

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
	logger.SetOutput(io.MultiWriter(os.Stderr, logFile))
}

// SetLogger replaces the underlying logger instance. Used by the Caddy
// integration to route output through Caddy's zap logger.
func SetLogger(l *log.Logger) {
	logger = l
}

func SetDebug(enabled bool) {
	debugEnabled = enabled
}

func logf(prefix, format string, v ...any) {
	logger.Printf("%s %s", prefix, fmt.Sprintf(format, v...))
}

func Debug(format string, v ...any) {
	if debugEnabled {
		logf("[DEB]", format, v...)
	}
}

func Info(format string, v ...any)   { logf("[INF]", format, v...) }
func Notice(format string, v ...any) { logf("[NOT]", format, v...) }
func Warn(format string, v ...any)   { logf("[WRN]", format, v...) }
func Error(format string, v ...any)  { logf("[ERR]", format, v...) }

func Fatal(format string, v ...any) {
	logger.Fatalf("[ERR] %s", fmt.Sprintf(format, v...))
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
