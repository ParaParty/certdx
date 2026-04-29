//go:build e2e

package harness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var (
	buildOnce sync.Once
	binDir    string
	buildErr  error
)

// repoRoot returns the absolute path to the certdx repository root.
func repoRoot(tb testing.TB) string {
	tb.Helper()
	// build.go lives at <repo>/test/e2e/harness/.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatalf("runtime.Caller failed")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	if err != nil {
		tb.Fatalf("resolving repo root: %s", err)
	}
	return root
}

// Binaries returns the directory holding freshly built certdx_server,
// certdx_client and certdx_tools. The build runs at most once per process.
func Binaries(tb testing.TB) string {
	tb.Helper()
	buildOnce.Do(func() {
		root := repoRoot(tb)
		dir, err := os.MkdirTemp("", "certdx-e2e-bin-*")
		if err != nil {
			buildErr = fmt.Errorf("mkdir tmp: %w", err)
			return
		}
		binDir = dir

		targets := []struct {
			name string
			dir  string
		}{
			{"certdx_server", filepath.Join(root, "exec", "server")},
			{"certdx_client", filepath.Join(root, "exec", "client")},
			{"certdx_tools", filepath.Join(root, "exec", "tools")},
		}
		for _, t := range targets {
			out := filepath.Join(binDir, t.name)
			cmd := exec.Command("go", "build", "-o", out, ".")
			cmd.Dir = t.dir
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if output, err := cmd.CombinedOutput(); err != nil {
				buildErr = fmt.Errorf("building %s: %w\n%s", t.name, err, output)
				return
			}
		}
	})
	if buildErr != nil {
		tb.Fatalf("build binaries: %s", buildErr)
	}
	return binDir
}

// ServerBin returns the absolute path of the built certdx_server.
func ServerBin(tb testing.TB) string { return filepath.Join(Binaries(tb), "certdx_server") }

// ClientBin returns the absolute path of the built certdx_client.
func ClientBin(tb testing.TB) string { return filepath.Join(Binaries(tb), "certdx_client") }

// ToolsBin returns the absolute path of the built certdx_tools.
func ToolsBin(tb testing.TB) string { return filepath.Join(Binaries(tb), "certdx_tools") }

// CleanupBinaries removes the temporary binary directory. Call from TestMain
// after m.Run(). Safe to call multiple times or before Binaries is invoked.
func CleanupBinaries() {
	if binDir == "" {
		return
	}
	_ = os.RemoveAll(binDir)
	binDir = ""
}
