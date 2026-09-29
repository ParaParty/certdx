// Package utils holds small, dependency-free helpers shared across certdx
// packages.
package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path so that readers, and a crash at any
// point, see either the previous contents or the new ones, never a partial
// file. The data is written and fsynced to a temp file in the same directory,
// which is then renamed over path; finally the directory itself is fsynced so
// the rename is durable. The directory sync is best-effort: some filesystems
// don't allow opening a directory for sync, and by then the new contents are
// already in place.
//
// perm is applied to the new file as is, independent of the umask.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op after rename succeeds

	if err := writeSynced(tmp, data, perm); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	syncDir(dir)

	return nil
}

// writeSynced writes data to f, sets its mode to perm and fsyncs it before
// closing, so the rename that follows can't expose a file whose contents
// never reached the disk. f is closed on every path.
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

// syncDir fsyncs dir so a rename inside it is durable. Failures are ignored:
// the file itself is already in place, and some filesystems don't allow
// opening a directory for sync.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}
