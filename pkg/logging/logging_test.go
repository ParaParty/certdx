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

func TestErrorLogger(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	el := ErrorLogger()
	el.Print("http: TLS handshake error from 1.2.3.4:1234: EOF")

	got := buf.String()
	if !strings.Contains(got, "[WRN]") {
		t.Fatalf("ErrorLogger output missing [WRN] prefix: %q", got)
	}
	if !strings.Contains(got, "http: TLS handshake error") {
		t.Fatalf("ErrorLogger output missing message body: %q", got)
	}
}

func TestLegoLoggerInfoPrefix(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	l := LegoLogger{}
	l.Printf("[INFO] [example.com] acme: Obtaining bundled SAN certificate")

	got := buf.String()
	if !strings.Contains(got, "[INF]") {
		t.Fatalf("LegoLogger [INFO] not mapped to [INF]: %q", got)
	}
	if strings.Contains(got, "[INFO]") {
		t.Fatalf("LegoLogger did not strip [INFO] prefix: %q", got)
	}
	if !strings.Contains(got, "[example.com] acme: Obtaining bundled SAN certificate") {
		t.Fatalf("LegoLogger lost message body: %q", got)
	}
}

func TestLegoLoggerWarnPrefix(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	l := LegoLogger{}
	l.Printf("[WARN] some acme warning")

	got := buf.String()
	if !strings.Contains(got, "[WRN]") {
		t.Fatalf("LegoLogger [WARN] not mapped to [WRN]: %q", got)
	}
	if strings.Contains(got, "[WARN]") {
		t.Fatalf("LegoLogger did not strip [WARN] prefix: %q", got)
	}
}

func TestLegoLoggerPlainPrint(t *testing.T) {
	buf, restore := captureLogger(t)
	defer restore()

	l := LegoLogger{}
	l.Print("plain message")

	got := buf.String()
	if !strings.Contains(got, "[INF]") {
		t.Fatalf("LegoLogger Print missing [INF] prefix: %q", got)
	}
	if !strings.Contains(got, "plain message") {
		t.Fatalf("LegoLogger Print missing message: %q", got)
	}
}
