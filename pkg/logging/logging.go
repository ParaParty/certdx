package logging

import (
	"fmt"
	"io"
	"log"
	"os"
)

var debugEnabled = false

func LogInit(logFilePath string) {
	log.SetOutput(os.Stderr)

	if logFilePath != "" {
		logFile, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, os.ModePerm)
		if err != nil {
			Error("Failed to open log file path: %s, error: %s", logFilePath, err)
			return
		}
		Info("Log to file path: %s", logFilePath)
		mw := io.MultiWriter(os.Stderr, logFile)
		log.SetOutput(mw)
	}
}

func SetDebug(enabled bool) {
	debugEnabled = enabled
}

func Debug(format string, v ...any) {
	if debugEnabled {
		log.Printf("[DEB] %s", fmt.Sprintf(format, v...))
	}
}

func Info(format string, v ...any) {
	log.Printf("[INF] %s", fmt.Sprintf(format, v...))
}

func Notice(format string, v ...any) {
	log.Printf("[NOT] %s", fmt.Sprintf(format, v...))
}

func Warn(format string, v ...any) {
	log.Printf("[WRN] %s", fmt.Sprintf(format, v...))
}

func Error(format string, v ...any) {
	log.Printf("[ERR] %s", fmt.Sprintf(format, v...))
}

func Fatal(format string, v ...any) {
	log.Fatalf("[ERR] %s", fmt.Sprintf(format, v...))
}

func Panic(format string, v ...any) {
	log.Panicf("[ERR] %s", fmt.Sprintf(format, v...))
}
