//go:build e2e

package e2e

import (
	"os"
	"testing"

	"pkg.para.party/certdx/test/e2e/harness"
)

// TestMain cleans up the shared binary directory after the suite finishes.
// Per-test temp dirs are cleaned by t.TempDir.
func TestMain(m *testing.M) {
	code := m.Run()
	harness.CleanupBinaries()
	os.Exit(code)
}
