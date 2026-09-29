package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileAtomicCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")

	if err := WriteFileAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %s", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %s", err)
	}
	if string(got) != "hello" {
		t.Fatalf("contents = %q, want %q", got, "hello")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %s", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("mode = %o, want 600", perm)
		}
	}
}

func TestWriteFileAtomicReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(path, []byte("a much longer previous content"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(path, []byte("new"), 0o640); err != nil {
		t.Fatalf("WriteFileAtomic: %s", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %s", err)
	}
	if string(got) != "new" {
		t.Fatalf("contents = %q, want %q", got, "new")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %s", err)
		}
		if perm := info.Mode().Perm(); perm != 0o640 {
			t.Fatalf("mode = %o, want 640", perm)
		}
	}
}

// No temp file may be left next to the target, on success or on failure.
func TestWriteFileAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	if err := WriteFileAtomic(path, []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %s", err)
	}

	// Renaming a file over a directory fails after the temp file is written.
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(blocked, []byte("nope"), 0o600); err == nil {
		t.Fatal("expected replacing a non-empty directory to fail")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 2 || names[0] != "blocked" || names[1] != "cache.json" {
		t.Fatalf("directory contents = %v, want [blocked cache.json]", names)
	}
}

func TestWriteFileAtomicFailsWhenDirectoryMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "cache.json")
	if err := WriteFileAtomic(path, []byte("x"), 0o600); err == nil {
		t.Fatal("expected an error writing into a missing directory")
	}
}
