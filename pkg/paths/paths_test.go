package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileExistsTrue(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "exists.txt")
	if err := os.WriteFile(p, []byte("hi"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !FileExists(p) {
		t.Fatalf("FileExists=false for existing file %s", p)
	}
}

func TestFileExistsFalse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "does-not-exist.txt")
	if FileExists(p) {
		t.Fatalf("FileExists=true for missing file %s", p)
	}
}

// TestSetMtlsDirOverride covers the --mtls-dir flag path:
// SetMtlsDir("/tmp/...") forces every Mtls*Path call to resolve under
// that directory, regardless of cwd / executable layout.
func TestSetMtlsDirOverride(t *testing.T) {
	prev := mtlsDirOverride
	t.Cleanup(func() { mtlsDirOverride = prev })

	dir := t.TempDir()
	override := filepath.Join(dir, "mtls-override")
	SetMtlsDir(override)

	got, err := MakeMtlsCertDir()
	if err != nil {
		t.Fatalf("MakeMtlsCertDir: %v", err)
	}
	if got != override {
		t.Fatalf("override not honored: got %s want %s", got, override)
	}

	// Directory should be created with 0o700.
	st, err := os.Stat(override)
	if err != nil {
		t.Fatalf("stat override dir: %v", err)
	}
	if !st.IsDir() {
		t.Fatalf("override not a dir")
	}
	// Permission bits — mask out the dir bit.
	if mode := st.Mode().Perm(); mode != 0o700 {
		t.Fatalf("override dir perm: got %o want 0o700", mode)
	}
}

func TestMtlsCAPathUnderOverride(t *testing.T) {
	prev := mtlsDirOverride
	t.Cleanup(func() { mtlsDirOverride = prev })
	override := filepath.Join(t.TempDir(), "mtls")
	SetMtlsDir(override)

	caPath, err := MtlsCAPath()
	if err != nil {
		t.Fatalf("MtlsCAPath: %v", err)
	}
	wantPEM := filepath.Join(override, "ca.pem")
	if caPath != wantPEM {
		t.Errorf("ca.pem path: got %s want %s", caPath, wantPEM)
	}
}

func TestMtlsBundlePathName(t *testing.T) {
	prev := mtlsDirOverride
	t.Cleanup(func() { mtlsDirOverride = prev })
	override := filepath.Join(t.TempDir(), "mtls")
	SetMtlsDir(override)

	p, err := MtlsBundlePath("alice")
	if err != nil {
		t.Fatalf("MtlsBundlePath: %v", err)
	}
	if p != filepath.Join(override, "alice.pem") {
		t.Errorf("bundle path: got %s", p)
	}
}
