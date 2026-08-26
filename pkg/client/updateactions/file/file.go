// Package file is the "file" update action: it writes renewed certificates
// to disk and runs an optional reload command.
//
// It deliberately does not import pkg/client, which registers it.
package file

import (
	"context"
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

type Action struct {
	cfg *config.FileAction
}

func New(cfg *config.FileAction) *Action {
	return &Action{cfg: cfg}
}

func (a *Action) Type() string {
	return config.UPDATE_ACTION_FILE
}

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

// prepareTempFile creates a temp file in dir, writes data with mode, and
// returns its path. The caller is responsible for renaming or removing it.
func prepareTempFile(dir, base string, data []byte, mode os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(dir, ".certdx-"+base+"-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return name, nil
}

// writeCertKeyPairAtomic writes fullchain and key to their respective paths
// in a best-effort atomic fashion. Both temp files are fully prepared before
// either rename is issued, so the window during which the on-disk cert/key
// pair is inconsistent is reduced to the span of two sequential rename
// syscalls rather than two full I/O operations.
func writeCertKeyPairAtomic(certPath string, fullchain []byte, keyPath string, key []byte) error {
	certTmp, err := prepareTempFile(filepath.Dir(certPath), filepath.Base(certPath), fullchain, permCertFile)
	if err != nil {
		return fmt.Errorf("prepare cert: %w", err)
	}
	defer func() { _ = os.Remove(certTmp) }() // no-op after rename succeeds

	keyTmp, err := prepareTempFile(filepath.Dir(keyPath), filepath.Base(keyPath), key, permKeyFile)
	if err != nil {
		return fmt.Errorf("prepare key: %w", err)
	}
	defer func() { _ = os.Remove(keyTmp) }() // no-op after rename succeeds

	// Rename both as close together as possible to minimise the window of
	// inconsistency between the cert and key files.
	if err := os.Rename(certTmp, certPath); err != nil {
		return fmt.Errorf("rename cert: %w", err)
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		return fmt.Errorf("rename key: %w", err)
	}
	return nil
}

// Update persists fullchain/key to the configured paths and invokes the
// optional reload command. File perms are tight: 0o644 for the public
// cert, 0o600 for the private key. Writes are atomic via rename, so
// partial-file reads are not possible.
//
// The reload command runs only when both files pre-existed; the first
// install is effectively a bootstrap and the downstream service is
// unlikely to be running yet. A failing reload command is logged but not
// returned: the certificate is already on disk, so retrying the whole
// action would rewrite identical bytes.
func (a *Action) Update(_ context.Context, fullchain, key []byte, c *config.ClientCertificate) error {
	certPath, keyPath, err := a.cfg.GetFullChainAndKeyPath(c.Name)
	if err != nil {
		return fmt.Errorf("get cert save path: %w", err)
	}

	certExists, err := ensureParentDir(certPath)
	if err != nil {
		return fmt.Errorf("save cert file: %w", err)
	}
	keyExists, err := ensureParentDir(keyPath)
	if err != nil {
		return fmt.Errorf("save cert file: %w", err)
	}

	if err := writeCertKeyPairAtomic(certPath, fullchain, keyPath, key); err != nil {
		return fmt.Errorf("save cert file: %w", err)
	}

	logging.Info("Saved cert %v", c.Domains)

	if certExists && keyExists {
		a.runReloadCommand()
	}

	return nil
}

func (a *Action) runReloadCommand() {
	// strings.Fields collapses whitespace and skips empty inputs, so
	// a whitespace-only ReloadCommand returns an empty slice — guard
	// against args[0] panicking instead of just !=  "".
	args := strings.Fields(a.cfg.ReloadCommand)
	if len(args) == 0 {
		return
	}

	logging.Debug("Executing reload command: %s", a.cfg.ReloadCommand)
	if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
		logging.Error("Failed executing reload command %s: %s", a.cfg.ReloadCommand, err)
	}
}
