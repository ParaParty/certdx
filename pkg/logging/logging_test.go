package logging

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func captureLogger(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	prev := logger
	prevDebug := debugEnabled
	buf := &bytes.Buffer{}
	logger = log.New(buf, "", 0)
	return buf, func() {
		logger = prev
		debugEnabled = prevDebug
	}
}

func TestDebugSuppressedByDefault(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	debugEnabled = false
	Debug("should not appear")

	if buf.Len() != 0 {
		t.Fatalf("Debug output when disabled: %q", buf.String())
	}
}

func TestDebugEnabledOutput(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	debugEnabled = true
	Debug("test %d", 42)

	got := buf.String()
	if !strings.Contains(got, "[DEB]") {
		t.Fatalf("missing [DEB] prefix: %q", got)
	}
	if !strings.Contains(got, "test 42") {
		t.Fatalf("missing message content: %q", got)
	}
}

func TestSetDebugToggles(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	SetDebug(true)
	Debug("visible")
	if !strings.Contains(buf.String(), "visible") {
		t.Fatal("Debug not visible after SetDebug(true)")
	}

	buf.Reset()
	SetDebug(false)
	Debug("invisible")
	if buf.Len() != 0 {
		t.Fatal("Debug visible after SetDebug(false)")
	}
}

func TestSetLoggerSwaps(t *testing.T) {
	prev := logger
	defer func() { logger = prev }()

	buf := &bytes.Buffer{}
	SetLogger(log.New(buf, "", 0))

	Info("routed")
	if !strings.Contains(buf.String(), "routed") {
		t.Fatal("SetLogger did not swap output")
	}
}

func TestInfoPrefix(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	Info("hello %s", "world")
	if !strings.Contains(buf.String(), "[INF]") {
		t.Fatalf("missing [INF] prefix: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "hello world") {
		t.Fatalf("missing message: %q", buf.String())
	}
}

func TestWarnPrefix(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	Warn("caution %d", 1)
	if !strings.Contains(buf.String(), "[WRN]") {
		t.Fatalf("missing [WRN] prefix: %q", buf.String())
	}
}

func TestErrorPrefix(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	Error("fail %s", "now")
	if !strings.Contains(buf.String(), "[ERR]") {
		t.Fatalf("missing [ERR] prefix: %q", buf.String())
	}
}

func TestNoticePrefix(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	Notice("note %s", "this")
	if !strings.Contains(buf.String(), "[NOT]") {
		t.Fatalf("missing [NOT] prefix: %q", buf.String())
	}
}
