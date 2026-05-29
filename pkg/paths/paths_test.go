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

// withDataDir installs override for the duration of the test.
func withDataDir(t *testing.T, dir string) {
	t.Helper()
	prev := dataDirOverride
	SetDataDir(dir)
	t.Cleanup(func() { SetDataDir(prev) })
}

func TestSetDataDirOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "data")
	withDataDir(t, override)

	mtls, err := MtlsDir()
	if err != nil {
		t.Fatalf("MtlsDir: %v", err)
	}
	if want := filepath.Join(override, "mtls"); mtls != want {
		t.Errorf("MtlsDir=%s want %s", mtls, want)
	}

	st, err := os.Stat(mtls)
	if err != nil {
		t.Fatalf("stat mtls: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o700 {
		t.Errorf("mtls perm: got %o want 0o700", mode)
	}

	keyPath, err := ACMEPrivateKey("u@example.com", "r3")
	if err != nil {
		t.Fatalf("ACMEPrivateKey: %v", err)
	}
	if want := filepath.Join(override, "private", "u@example.com_r3.key"); keyPath != want {
		t.Errorf("ACMEPrivateKey=%s want %s", keyPath, want)
	}

	cache, err := ServerCachePath()
	if err != nil {
		t.Fatalf("ServerCachePath: %v", err)
	}
	if want := filepath.Join(override, "cache.json"); cache != want {
		t.Errorf("ServerCachePath=%s want %s", cache, want)
	}
}

func TestMtlsBundlePathName(t *testing.T) {
	override := filepath.Join(t.TempDir(), "data")
	withDataDir(t, override)

	p, err := MtlsBundlePath("alice")
	if err != nil {
		t.Fatalf("MtlsBundlePath: %v", err)
	}
	if want := filepath.Join(override, "mtls", "alice.pem"); p != want {
		t.Errorf("bundle path: got %s want %s", p, want)
	}
}

func TestMtlsCAAndCounterPath(t *testing.T) {
	override := filepath.Join(t.TempDir(), "data")
	withDataDir(t, override)

	ca, err := MtlsCAPath()
	if err != nil {
		t.Fatalf("MtlsCAPath: %v", err)
	}
	if want := filepath.Join(override, "mtls", "ca.pem"); ca != want {
		t.Errorf("MtlsCAPath=%s want %s", ca, want)
	}

	counter, err := CACounterPath()
	if err != nil {
		t.Fatalf("CACounterPath: %v", err)
	}
	if want := filepath.Join(override, "mtls", "counter.txt"); counter != want {
		t.Errorf("CACounterPath=%s want %s", counter, want)
	}
}
