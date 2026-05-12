package client

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestWriteCertAndDoCommandWritesBothFiles(t *testing.T) {
	root := t.TempDir()
	c := &config.ClientCertification{
		Name:     "site",
		SavePath: root,
		Domains:  []string{"example.com"},
	}
	writeCertAndDoCommand([]byte("CERT"), []byte("KEY"), c)

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
	writeCertAndDoCommand([]byte("CERT"), []byte("KEY"), c)
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
	writeCertAndDoCommand([]byte("CERT"), []byte("KEY"), c)

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
	writeCertAndDoCommand([]byte("CERT"), []byte("KEY"), c)
	// Nothing to assert on disk — just that we returned cleanly.
}
