package client

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
)

// File permissions for written material.
const (
	permCertDir  os.FileMode = 0o755
	permCertFile os.FileMode = 0o644
	permKeyFile  os.FileMode = 0o600
)

// CertificateUpdateHandler is invoked whenever a watched cert receives
// fresh material. Handlers are expected to be quick; long-running work
// should be dispatched elsewhere.
type CertificateUpdateHandler func(fullchain, key []byte, c *config.ClientCertification)

// ensureParentDir creates file's parent directory if needed. It reports
// whether file already existed before we had the chance to write it.
func ensureParentDir(file string) (exists bool, err error) {
	if _, err = os.Stat(file); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}

	dir := filepath.Dir(file)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, permCertDir); err != nil {
			return false, fmt.Errorf("create %s: %w", dir, err)
		}
	} else if err != nil {
		return false, err
	}
	return false, nil
}

// writeFileAtomic writes data to path with the given mode using a
// temp-file-then-rename dance, so readers (e.g. an nginx reloading the
// cert) never observe a torn file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".certdx-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// If we never made it to rename, clean up the stray temp file.
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}

// writeCertAndDoCommand persists fullchain/key to the paths configured
// for c and invokes the optional reload command. File perms are tight:
// 0o644 for the public cert, 0o600 for the private key. Writes are
// atomic via rename, so partial-file reads are not possible.
//
// The reload command runs only when both files pre-existed; the first
// install is effectively a bootstrap and the downstream service is
// unlikely to be running yet.
func writeCertAndDoCommand(fullchain, key []byte, c *config.ClientCertification) {
	var certExists, keyExists bool

	certPath, keyPath, err := c.GetFullChainAndKeyPath()
	if err != nil {
		logging.Debug("Failed to get cert save path: %s", err)
		return
	}
	certExists, err = ensureParentDir(certPath)
	if err != nil {
		goto ERR
	}
	keyExists, err = ensureParentDir(keyPath)
	if err != nil {
		goto ERR
	}

	if err = writeFileAtomic(certPath, fullchain, permCertFile); err != nil {
		goto ERR
	}
	if err = writeFileAtomic(keyPath, key, permKeyFile); err != nil {
		goto ERR
	}

	if certExists && keyExists {
		// strings.Fields collapses whitespace and skips empty inputs, so
		// a whitespace-only ReloadCommand returns an empty slice — guard
		// against args[0] panicking instead of just !=  "".
		if args := strings.Fields(c.ReloadCommand); len(args) > 0 {
			if err = exec.Command(args[0], args[1:]...).Run(); err != nil {
				logging.Error("Failed executing reload command %s: %s", c.ReloadCommand, err)
			}
		}
	}
	return

ERR:
	logging.Error("Failed to save cert file: %s", err)
}
