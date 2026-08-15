package client

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"pkg.para.party/certdx/pkg/config"
)

func TestEnsureParentDirCreatesMissingDir(t *testing.T) {
	root := t.TempDir()
	// nested/dir doesn't exist yet, the parent must be created.
	target := filepath.Join(root, "nested", "dir", "cert.pem")

	exists, err := ensureParentDir(target)
	if err != nil {
		t.Fatalf("ensureParentDir: %v", err)
	}
	if exists {
		t.Fatalf("exists=true for not-yet-created file")
	}
	st, err := os.Stat(filepath.Dir(target))
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if !st.IsDir() {
		t.Fatalf("parent is not a dir")
	}
	if mode := st.Mode().Perm(); mode != permCertDir {
		t.Errorf("parent dir perm: got %o want %o", mode, permCertDir)
	}
}

func TestEnsureParentDirReportsExisting(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "cert.pem")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	exists, err := ensureParentDir(target)
	if err != nil {
		t.Fatalf("ensureParentDir: %v", err)
	}
	if !exists {
		t.Fatalf("exists=false for existing file")
	}
}

func TestPrepareTempFileCreatesAndChmods(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "cert.pem")
	want := []byte("PEM-fullchain")

	tmp, err := prepareTempFile(root, "cert.pem", want, 0o600)
	if err != nil {
		t.Fatalf("prepareTempFile: %v", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read after write: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("contents mismatch:\n got %q\n want %q", got, want)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("perm mismatch: got %o want %o", mode, 0o600)
	}
}

func TestPrepareTempFileReplacesExisting(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "cert.pem")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tmp, err := prepareTempFile(root, "cert.pem", []byte("new"), 0o600)
	if err != nil {
		t.Fatalf("prepareTempFile: %v", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("contents not replaced: got %q", got)
	}
	st, _ := os.Stat(p)
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Fatalf("perm not chmod'd: got %o want %o", mode, 0o600)
	}
}

// TestPrepareTempFileMissingDir exercises the error path: pointing at a
// non-existent dir should fail on CreateTemp and surface a "create temp
// file:" wrapped error, leaving no stray files behind.
func TestPrepareTempFileMissingDir(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := prepareTempFile(missingDir, "cert.pem", []byte("x"), 0o600)
	if err == nil {
		t.Fatal("expected error for missing parent dir")
	}
	if !strings.Contains(err.Error(), "create temp file") {
		t.Errorf("error wrap: %v", err)
	}
}

// TestPrepareTempFileSurvivesFsyncFailure pins the best-effort fsync:
// some FUSE/container mounts answer fsync with ENOSYS/EINVAL, and that
// must not stop a certificate write that would otherwise land.
func TestPrepareTempFileSurvivesFsyncFailure(t *testing.T) {
	orig := syncFile
	t.Cleanup(func() { syncFile = orig })
	syncFile = func(*os.File) error { return syscall.ENOSYS }

	root := t.TempDir()
	p := filepath.Join(root, "cert.pem")
	tmp, err := prepareTempFile(root, "cert.pem", []byte("CERT"), 0o600)
	if err != nil {
		t.Fatalf("fsync failure must not fail the write: %v", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got, err := os.ReadFile(p); err != nil || string(got) != "CERT" {
		t.Fatalf("contents: got %q err %v", got, err)
	}
}

// TestWriteCertAndDoCommandSurvivesFsyncFailure walks the same mount
// through the full write path: a refused fsync must still deliver both
// cert and key.
func TestWriteCertAndDoCommandSurvivesFsyncFailure(t *testing.T) {
	orig := syncFile
	t.Cleanup(func() { syncFile = orig })
	syncFile = func(*os.File) error { return syscall.EINVAL }

	root := t.TempDir()
	c := &config.ClientCertification{
		Name:     "site",
		SavePath: root,
		Domains:  []string{"example.com"},
	}
	writeCertAndDoCommand(context.Background(), []byte("CERT"), []byte("KEY"), c)

	if got, err := os.ReadFile(filepath.Join(root, "site.pem")); err != nil || string(got) != "CERT" {
		t.Fatalf("cert not delivered on a mount that refuses fsync: got %q err %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "site.key")); err != nil || string(got) != "KEY" {
		t.Fatalf("key not delivered on a mount that refuses fsync: got %q err %v", got, err)
	}
}

func TestWriteCertAndDoCommandWritesBothFiles(t *testing.T) {
	root := t.TempDir()
	c := &config.ClientCertification{
		Name:     "site",
		SavePath: root,
		Domains:  []string{"example.com"},
	}
	writeCertAndDoCommand(context.Background(), []byte("CERT"), []byte("KEY"), c)

	cert, err := os.ReadFile(filepath.Join(root, "site.pem"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(cert) != "CERT" {
		t.Errorf("cert contents: got %q want %q", cert, "CERT")
	}
	key, err := os.ReadFile(filepath.Join(root, "site.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(key) != "KEY" {
		t.Errorf("key contents: got %q want %q", key, "KEY")
	}

	// Key must be 0o600.
	st, _ := os.Stat(filepath.Join(root, "site.key"))
	if mode := st.Mode().Perm(); mode != permKeyFile {
		t.Errorf("key perm: got %o want %o", mode, permKeyFile)
	}
	// Cert must be 0o644.
	st, _ = os.Stat(filepath.Join(root, "site.pem"))
	if mode := st.Mode().Perm(); mode != permCertFile {
		t.Errorf("cert perm: got %o want %o", mode, permCertFile)
	}
}

// TestWriteCertAndDoCommandWhitespaceReloadCommand pins the
// `strings.Fields(...)` empty-slice guard added in PR #65: a
// whitespace-only ReloadCommand must not panic args[0].
func TestWriteCertAndDoCommandWhitespaceReloadCommand(t *testing.T) {
	root := t.TempDir()
	c := &config.ClientCertification{
		Name:          "site",
		SavePath:      root,
		ReloadCommand: "   \t  ",
	}
	// Pre-create both files so the reload-command branch is taken.
	if err := os.WriteFile(filepath.Join(root, "site.pem"), []byte("old"), 0o644); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "site.key"), []byte("old"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on whitespace ReloadCommand: %v", r)
		}
	}()
	writeCertAndDoCommand(context.Background(), []byte("CERT"), []byte("KEY"), c)
}

// TestWriteCertAndDoCommandSkipsReloadOnFirstInstall covers the
// bootstrap-vs-rotation contract documented in docs/client.md: when
// the cert files are not yet on disk, the reload command must NOT
// run. We force that by using a sentinel reload command that would
// fail noisily (`/nonexistent/should-not-run`); since the files do
// not pre-exist, the command should never be invoked.
func TestWriteCertAndDoCommandSkipsReloadOnFirstInstall(t *testing.T) {
	root := t.TempDir()
	c := &config.ClientCertification{
		Name:          "site",
		SavePath:      root,
		ReloadCommand: "/nonexistent/should-not-run",
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked: %v", r)
		}
	}()
	// First install — files don't exist yet — reload must not run.
	writeCertAndDoCommand(context.Background(), []byte("CERT"), []byte("KEY"), c)

	if _, err := os.Stat(filepath.Join(root, "site.pem")); err != nil {
		t.Errorf("cert was not written: %v", err)
	}
}

// TestWriteCertAndDoCommandEmptySavePath covers the early-return path
// when GetFullChainAndKeyPath fails because SavePath is empty.
func TestWriteCertAndDoCommandEmptySavePath(t *testing.T) {
	c := &config.ClientCertification{Name: "site", SavePath: ""}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on empty save path: %v", r)
		}
	}()
	writeCertAndDoCommand(context.Background(), []byte("CERT"), []byte("KEY"), c)
	// Nothing to assert on disk — just that we returned cleanly.
}

// TestRunReloadCommandKillsHungCommand pins the hang fix: a reload
// command that never exits must be killed at the timeout so the sole
// UpdateChan consumer regains control.
func TestRunReloadCommandKillsHungCommand(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		runReloadCommand(context.Background(), "sleep 30", 100*time.Millisecond)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runReloadCommand did not return, hung reload wedges the watcher")
	}
}

// TestRunReloadCommandHonoursContext covers the daemon-stop path: a
// cancelled root context must terminate the reload command too.
func TestRunReloadCommandHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runReloadCommand(ctx, "sleep 30", time.Minute)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runReloadCommand ignored context cancellation")
	}
}

// TestWriteCertKeyPairAtomicSeparateDirs covers cert and key living in
// different directories: both renames must land, and the parent-dir
// syncs must not turn a successful write into an error.
func TestWriteCertKeyPairAtomicSeparateDirs(t *testing.T) {
	certDir := t.TempDir()
	keyDir := t.TempDir()
	certPath := filepath.Join(certDir, "site.pem")
	keyPath := filepath.Join(keyDir, "site.key")

	if err := writeCertKeyPairAtomic(certPath, []byte("CERT"), keyPath, []byte("KEY")); err != nil {
		t.Fatalf("writeCertKeyPairAtomic: %v", err)
	}
	if got, err := os.ReadFile(certPath); err != nil || string(got) != "CERT" {
		t.Fatalf("cert: got %q err %v", got, err)
	}
	if got, err := os.ReadFile(keyPath); err != nil || string(got) != "KEY" {
		t.Fatalf("key: got %q err %v", got, err)
	}
}

// TestSyncDirMissingDirIsBestEffort: syncing a directory that isn't
// there must not panic — the sync is durability polish, not a
// precondition.
func TestSyncDirMissingDirIsBestEffort(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked: %v", r)
		}
	}()
	syncDir(filepath.Join(t.TempDir(), "nope"))
}
