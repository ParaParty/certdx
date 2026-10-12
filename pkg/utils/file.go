// Package utils holds small helpers shared across certdx packages.
package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic replaces path with data so that a crash leaves either the
// old or the new contents, never a partial file. perm is applied regardless
// of the umask.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmpPath, err := WriteTempFile(path, data, perm)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath) // no-op once renamed

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	SyncDir(filepath.Dir(path))
	return nil
}

// WriteTempFile writes data with perm to a new hidden file next to path and
// returns its name. The caller renames or removes it.
func WriteTempFile(path string, data []byte, perm os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	if err := writeSynced(tmp, data, perm); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("write temp file: %w", err)
	}
	return tmp.Name(), nil
}

// writeSynced writes data to f, sets perm and fsyncs before closing f.
func writeSynced(f *os.File, data []byte, perm os.FileMode) error {
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// SyncDir fsyncs dir so a rename inside it survives a crash. Errors are
// ignored: some filesystems can't sync a directory, and the rename is done.
func SyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}
