//go:build e2e

package harness

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Process wraps a running certdx subprocess (server or client) with helpers
// for log capture and graceful stop.
type Process struct {
	tb     testing.TB
	cmd    *exec.Cmd
	stdout *syncBuf
	stderr *syncBuf
	logTag string
	done   chan struct{}
	waitOk bool
	waitMu sync.Mutex
}

type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Start launches bin with args under cwd. Stdout/stderr are captured into
// in-memory buffers and tee'd to <cwd>/logs/.
func Start(tb testing.TB, logTag, bin, cwd string, args ...string) *Process {
	return StartEnv(tb, logTag, bin, cwd, nil, args...)
}

// StartEnv is Start with extra environment variables appended to os.Environ.
func StartEnv(tb testing.TB, logTag, bin, cwd string, extraEnv []string, args ...string) *Process {
	tb.Helper()

	logsDir := filepath.Join(cwd, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		tb.Fatalf("mkdir logs: %s", err)
	}
	stdoutFile, err := os.Create(filepath.Join(logsDir, logTag+".stdout.log"))
	if err != nil {
		tb.Fatalf("create stdout log: %s", err)
	}
	stderrFile, err := os.Create(filepath.Join(logsDir, logTag+".stderr.log"))
	if err != nil {
		tb.Fatalf("create stderr log: %s", err)
	}

	cmd := exec.Command(bin, args...)
	cmd.Dir = cwd
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	stdout := &syncBuf{}
	stderr := &syncBuf{}
	cmd.Stdout = io.MultiWriter(stdout, stdoutFile)
	cmd.Stderr = io.MultiWriter(stderr, stderrFile)

	if err := cmd.Start(); err != nil {
		tb.Fatalf("start %s: %s", logTag, err)
	}

	p := &Process{
		tb:     tb,
		cmd:    cmd,
		stdout: stdout,
		stderr: stderr,
		logTag: logTag,
		done:   make(chan struct{}),
	}

	go func() {
		err := cmd.Wait()
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
		p.waitMu.Lock()
		if err == nil {
			p.waitOk = true
		}
		p.waitMu.Unlock()
		close(p.done)
	}()

	tb.Cleanup(func() {
		p.Stop(3 * time.Second)
		if tb.Failed() {
			tb.Logf("=== %s stdout ===\n%s", p.logTag, p.stdout.String())
			tb.Logf("=== %s stderr ===\n%s", p.logTag, p.stderr.String())
		}
	})

	return p
}

// Stop sends SIGTERM and waits up to timeout, then SIGKILLs if needed.
func (p *Process) Stop(timeout time.Duration) {
	if p.cmd.Process == nil {
		return
	}
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(timeout):
		_ = p.cmd.Process.Signal(syscall.SIGKILL)
		<-p.done
	}
}

// GracefulStop sends SIGTERM and waits up to timeout. Unlike Stop it does
// NOT escalate to SIGKILL. Returns true iff the process exited in time.
func (p *Process) GracefulStop(timeout time.Duration) bool {
	if p.cmd.Process == nil {
		return true
	}
	select {
	case <-p.done:
		return true
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Stdout returns a snapshot of stdout so far.
func (p *Process) Stdout() string { return p.stdout.String() }

// Stderr returns a snapshot of stderr so far.
func (p *Process) Stderr() string { return p.stderr.String() }

// CombinedOutput returns stdout+stderr concatenated.
func (p *Process) CombinedOutput() string { return p.stdout.String() + "\n" + p.stderr.String() }

// WaitForExit blocks until the process exits or timeout elapses. Returns
// true if it exited in time.
func (p *Process) WaitForExit(timeout time.Duration) bool {
	select {
	case <-p.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// WaitListening polls host:port with TCP dials until one succeeds or
// timeout elapses.
func WaitListening(host string, port int, timeout time.Duration) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

// WaitNotListening polls host:port until a TCP dial fails (listener gone)
// or timeout elapses. Used between stop/restart cycles to avoid races on
// the freshly freed port.
func WaitNotListening(host string, port int, timeout time.Duration) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return nil
		}
		_ = c.Close()
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s to stop listening", addr)
}

// RunTool runs certdx_tools with args under cwd, returning combined output.
// The call must complete within ctx.
func RunTool(ctx context.Context, tb testing.TB, cwd string, args ...string) (string, error) {
	tb.Helper()
	bin := ToolsBin(tb)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	return string(out), err
}
