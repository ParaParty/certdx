//go:build e2e

package harness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	caddyOnce sync.Once
	caddyPath string
	caddyErr  error
)

// CaddyBin returns the absolute path of a freshly built caddy binary that
// embeds the certdx caddytls plugin (built via xcaddy from the local
// checkout). The build runs at most once per process and lands inside the
// shared binary directory created by Binaries(), so CleanupBinaries()
// reaps it together with the other binaries.
//
// xcaddy must be installed and discoverable on PATH (or under
// $(go env GOBIN), $(go env GOPATH)/bin, or ~/go/bin). If it is missing
// the test fails with an instructive error.
func CaddyBin(tb testing.TB) string {
	tb.Helper()
	dir := Binaries(tb)
	caddyOnce.Do(func() {
		xcaddy, err := findXCaddy()
		if err != nil {
			caddyErr = err
			return
		}
		root := repoRoot(tb)
		out := filepath.Join(dir, "caddy")
		cmd := exec.Command(
			xcaddy, "build",
			"--with", "pkg.para.party/certdx/exec/caddytls="+filepath.Join(root, "exec", "caddytls"),
			"--replace", "pkg.para.party/certdx="+root,
			"--output", out,
		)
		// xcaddy creates a temporary build directory; force module mode so
		// our --replace flag is honored even when the repo's go.work file
		// would otherwise put Go into workspace mode.
		cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
		if output, err := cmd.CombinedOutput(); err != nil {
			caddyErr = fmt.Errorf("xcaddy build: %w\n%s", err, output)
			return
		}
		caddyPath = out
	})
	if caddyErr != nil {
		tb.Fatalf("build caddy: %s", caddyErr)
	}
	return caddyPath
}

// findXCaddy locates the xcaddy executable. PATH is consulted first, then
// $(go env GOBIN), $(go env GOPATH)/bin, and finally ~/go/bin.
func findXCaddy() (string, error) {
	if p, err := exec.LookPath("xcaddy"); err == nil {
		return p, nil
	}
	candidates := []string{}
	if v := goEnv("GOBIN"); v != "" {
		candidates = append(candidates, filepath.Join(v, "xcaddy"))
	}
	if v := goEnv("GOPATH"); v != "" {
		candidates = append(candidates, filepath.Join(v, "bin", "xcaddy"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "go", "bin", "xcaddy"))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("xcaddy not found on PATH or in GOBIN/GOPATH/~/go/bin; install with: go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest")
}

func goEnv(name string) string {
	out, err := exec.Command("go", "env", name).Output()
	if err != nil {
		return ""
	}
	s := string(out)
	// strip trailing newline
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
