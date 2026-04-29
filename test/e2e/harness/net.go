//go:build e2e

package harness

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// FreePort returns a TCP port that was free at the moment of the call.
// There is an inherent race between closing the probe listener and the
// caller binding the port; acceptable for local/CI use.
func FreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("listen :0: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port, nil
}

// MustFreePort returns a free port or panics. Test setup only.
func MustFreePort() int {
	p, err := FreePort()
	if err != nil {
		panic(err)
	}
	return p
}

// StartTarpit binds a TCP listener on 127.0.0.1:port that accepts and
// immediately closes connections. Used by graceful-stop tests as a
// fast-failing stand-in for a broken certdx_server: Stream() errors out
// quickly and the client settles into its interruptible retry-sleep.
//
// A tarpit that holds connections open without completing the TLS
// handshake would instead trigger a known limitation in pkg/client/sds.go
// where StreamSecrets uses an uncancellable context.
//
// The listener is closed via tb.Cleanup.
func StartTarpit(tb testing.TB, port int) net.Listener {
	tb.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var ln net.Listener
	var err error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		tb.Fatalf("tarpit listen %s: %s", addr, err)
	}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	tb.Cleanup(func() { _ = ln.Close() })
	return ln
}
