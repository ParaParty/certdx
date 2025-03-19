package logging

import (
	"fmt"
	"io"
	"log"
	"os"
)

var debugEnabled = false
var logger *log.Logger = log.New(os.Stderr, "", log.LstdFlags)

func SetLogFile(logFilePath string) {
	if logFilePath != "" {
		logFile, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, os.ModePerm)
		if err != nil {
			Error("Failed to open log file path: %s, error: %s", logFilePath, err)
			return
		}
		Info("Log to file path: %s", logFilePath)
		mw := io.MultiWriter(os.Stderr, logFile)
		logger.SetOutput(mw)
	}
}

func SetLogger(l *log.Logger) {
	logger = l
}

func SetDebug(enabled bool) {
	debugEnabled = enabled
}

func Debug(format string, v ...any) {
	if debugEnabled {
		logger.Printf("[DEB] %s", fmt.Sprintf(format, v...))
	}
}

func Info(format string, v ...any) {
	logger.Printf("[INF] %s", fmt.Sprintf(format, v...))
}

func Notice(format string, v ...any) {
	logger.Printf("[NOT] %s", fmt.Sprintf(format, v...))
}

func Warn(format string, v ...any) {
	logger.Printf("[WRN] %s", fmt.Sprintf(format, v...))
}

func Error(format string, v ...any) {
	logger.Printf("[ERR] %s", fmt.Sprintf(format, v...))
}

func Fatal(format string, v ...any) {
	logger.Fatalf("[ERR] %s", fmt.Sprintf(format, v...))
}

func Panic(format string, v ...any) {
	logger.Panicf("[ERR] %s", fmt.Sprintf(format, v...))
}
