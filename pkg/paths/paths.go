// Package paths centralizes how certdx resolves the on-disk locations it
// reads and writes.
//
// Two roots are distinguished:
//
//   - Config root: holds the mtls/ bundle directory (cert material is
//     treated as configuration, not runtime state). FHS default
//     /etc/certdx; Local default is the directory containing the
//     resolved executable.
//   - State root: holds runtime state (cache.json, private/ ACME
//     account keys). FHS default /var/lib/certdx; Local default is the
//     directory containing the resolved executable.
//
// SetDataDir provides a single override that collapses both roots to
// the same directory; this is what --data-dir / CERTDX_DATA_DIR set,
// and is what tarball installs and tests rely on.
//
// Config-file location is the caller's responsibility (--conf is
// required) and is independent of these roots.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	MtlsCertificateDir = "mtls"
	ACMEPrivateKeyDir  = "private"
	ServerCacheFile    = "cache.json"

	fhsConfigDir = "/etc/certdx"
	fhsStateDir  = "/var/lib/certdx"
)

var dataDirOverride string

// FileExists reports whether the file at p exists. Returns false on any
// stat error, including permission errors.
func FileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// SetDataDir sets a process-local override that collapses both the
// config and state roots onto dir. Used by --data-dir / CERTDX_DATA_DIR.
// Call once during process setup; concurrent mutation is not supported.
func SetDataDir(dir string) {
	dataDirOverride = dir
}

func isFHSInstall() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	switch filepath.Dir(exe) {
	case "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin":
		return true
	}
	return false
}

func localBaseDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return filepath.Dir(exe), nil
}

func configRoot() (string, error) {
	if dataDirOverride != "" {
		return dataDirOverride, nil
	}
	if isFHSInstall() {
		return fhsConfigDir, nil
	}
	return localBaseDir()
}

func stateRoot() (string, error) {
	if dataDirOverride != "" {
		return dataDirOverride, nil
	}
	if isFHSInstall() {
		return fhsStateDir, nil
	}
	return localBaseDir()
}

// MtlsDir returns the directory for mtls material, creating it with
// mode 0o700 if necessary.
func MtlsDir() (string, error) {
	root, err := configRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, MtlsCertificateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func MtlsCAPath() (string, error) {
	dir, err := MtlsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ca.pem"), nil
}

func CACounterPath() (string, error) {
	dir, err := MtlsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "counter.txt"), nil
}

func MtlsBundlePath(name string) (string, error) {
	dir, err := MtlsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".pem"), nil
}

func ACMEPrivateKey(email, acmeProvider string) (string, error) {
	root, err := stateRoot()
	if err != nil {
		return "", err
	}
	saveDir := filepath.Join(root, ACMEPrivateKeyDir)
	if err := os.MkdirAll(saveDir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create path: %s to save account key: %w", saveDir, err)
	}
	keyName := fmt.Sprintf("%s_%s.key", email, acmeProvider)
	return filepath.Join(saveDir, keyName), nil
}

// ServerCachePath returns the on-disk path to the server's persisted
// cert cache, creating its parent directory if necessary.
func ServerCachePath() (string, error) {
	root, err := stateRoot()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(root, ServerCacheFile), nil
}
