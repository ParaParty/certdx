// Package paths centralizes how certdx resolves the on-disk locations it
// reads and writes: the mtls directory (CA, server, client material), the
// ACME account private-key directory, and the server cache file.
//
// The discovery rule is unchanged from the previous pkg/utils.findFile
// behavior: look in the current working directory first, then next to the
// running executable. If neither exists, the create paths fall back to the
// directory containing the executable. This preserves backward compatibility
// with existing deployments that rely on either layout.
package paths

import (
	"fmt"
	"os"
	"path"
)

const (
	// MtlsCertificateDir is the conventional directory name for mtls
	// material under either the cwd or the exec dir.
	MtlsCertificateDir = "mtls"

	// ACMEPrivateKeyDir is the conventional directory name for ACME
	// account private keys.
	ACMEPrivateKeyDir = "private"

	// ServerCacheFile is the conventional file name for the server's
	// persisted cert cache.
	ServerCacheFile = "cache.json"
)

var mtlsDirOverride string

// FileExists reports whether the file at path exists. It returns false on
// any stat error, including permission errors, so callers should not rely on
// FileExists to distinguish "missing" from "unreadable".
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// SetMtlsDir sets a process-local mtls directory override. It is mainly used
// by --mtls-dir flags.
func SetMtlsDir(dir string) {
	mtlsDirOverride = dir
}

func ensureMtlsDir(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// findFile looks up file under the cwd, then under the directory containing
// the running executable. It returns the first hit, or os.ErrNotExist if
// neither exists.
func findFile(file string) (string, error) {
	cwd, err := os.Getwd()
	if err == nil {
		pa := path.Join(cwd, file)
		if FileExists(pa) {
			return pa, nil
		}
	}

	exec, err := os.Executable()
	if err == nil {
		pa := path.Join(exec, file)
		if FileExists(pa) {
			return pa, nil
		}
	}

	return "", os.ErrNotExist
}

// MakeMtlsCertDir resolves the mtls directory for read/write use. It
// returns an existing directory if one is found via discovery; otherwise it
// creates a fresh mtls directory under the directory containing the
// running executable and returns the new path.
func MakeMtlsCertDir() (string, error) {
	if mtlsDirOverride != "" {
		return ensureMtlsDir(mtlsDirOverride)
	}

	dir, err := findFile(MtlsCertificateDir)
	if err == nil {
		return ensureMtlsDir(dir)
	}

	exec, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir = path.Dir(exec)

	dir = path.Join(dir, MtlsCertificateDir)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	return ensureMtlsDir(dir)
}

// MtlsCAPath returns the on-disk paths to the mtls CA certificate (PEM) and
// CA private key.
func MtlsCAPath() (caPEMPath, caKeyPath string, err error) {
	caDir, err := MakeMtlsCertDir()
	if err != nil {
		return
	}

	caPEMPath = path.Join(caDir, "ca.pem")
	caKeyPath = path.Join(caDir, "ca.key")
	return
}

// CACounterPath returns the on-disk path to the CA serial counter file.
func CACounterPath() (caCounterPath string, err error) {
	caDir, err := MakeMtlsCertDir()
	if err != nil {
		return
	}

	caCounterPath = path.Join(caDir, "counter.txt")
	return
}

// MtlsServerCertPath returns the on-disk paths to the mtls server certificate
// (PEM) and server private key.
func MtlsServerCertPath() (certPEMPath, certKeyPath string, err error) {
	caDir, err := MakeMtlsCertDir()
	if err != nil {
		return
	}

	certPEMPath = path.Join(caDir, "server.pem")
	certKeyPath = path.Join(caDir, "server.key")
	return
}

// MtlsClientCertPath returns the on-disk paths to a named mtls client
// certificate (PEM) and client private key.
func MtlsClientCertPath(name string) (certPEMPath, certKeyPath string, err error) {
	caDir, err := MakeMtlsCertDir()
	if err != nil {
		return
	}

	certPEMPath = path.Join(caDir, fmt.Sprintf("%s.pem", name))
	certKeyPath = path.Join(caDir, fmt.Sprintf("%s.key", name))
	return
}

// ACMEPrivateKey returns the on-disk path to an ACME account private key
// for the given email + provider pair.
func ACMEPrivateKey(email, acmeProvider string) (string, error) {
	keyName := fmt.Sprintf("%s_%s.key", email, acmeProvider)

	saveDir, err := findFile(ACMEPrivateKeyDir)
	if err == nil {
		return path.Join(saveDir, keyName), nil
	}

	exec, err := os.Executable()
	if err != nil {
		return "", err
	}
	saveDir = path.Dir(exec)

	saveDir = path.Join(saveDir, ACMEPrivateKeyDir)

	if _, err := os.Stat(saveDir); os.IsNotExist(err) {
		if err := os.Mkdir(saveDir, 0o755); err != nil {
			return "", fmt.Errorf("cannot create path: %s to save account key: %w", saveDir, err)
		}
	} else if err != nil {
		return "", err
	}

	return path.Join(saveDir, keyName), nil
}

// ServerCacheSave returns the on-disk path to the server's persisted cert
// cache. Discovery looks in the cwd, then next to the executable; if
// neither exists, the cache file is placed next to the executable.
func ServerCacheSave() string {
	cacheFile, err := findFile(ServerCacheFile)
	if err == nil {
		return cacheFile
	}

	exec, err := os.Executable()
	if err != nil {
		return ServerCacheFile
	}
	saveDir := path.Dir(exec)

	return path.Join(saveDir, ServerCacheFile)
}
