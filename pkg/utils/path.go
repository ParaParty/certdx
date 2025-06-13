package utils

import (
	"fmt"
	"os"
	"path"
)

const (
	MTLS_CERTIFICATE_DIR = "mtls"
	ACME_PRIVATE_KEY_DIR = "private"
	SERVER_CACHE_FILE    = "cache.json"
)

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

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

func MakeMtlsCertDir() (string, error) {
	dir, err := findFile(MTLS_CERTIFICATE_DIR)
	if err == nil {
		return dir, nil
	}

	exec, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir = path.Dir(exec)

	dir = path.Join(dir, MTLS_CERTIFICATE_DIR)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.Mkdir(dir, 0o777)
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	return dir, nil
}

func GetMtlsCAPath() (caPEMPath, caKeyPath string, err error) {
	caDir, err := MakeMtlsCertDir()
	if err != nil {
		return
	}

	caPEMPath = path.Join(caDir, "ca.pem")
	caKeyPath = path.Join(caDir, "ca.key")
	return
}

func GetCACounterPath() (caCounterPath string, err error) {
	caDir, err := MakeMtlsCertDir()
	if err != nil {
		return
	}

	caCounterPath = path.Join(caDir, "counter.txt")
	return
}

func GetMtlsServerCertPath() (certPEMPath, certKeyPath string, err error) {
	caDir, err := MakeMtlsCertDir()
	if err != nil {
		return
	}

	certPEMPath = path.Join(caDir, "server.pem")
	certKeyPath = path.Join(caDir, "server.key")
	return
}

func GetMtlsClientCertPath(name string) (certPEMPath, certKeyPath string, err error) {
	caDir, err := MakeMtlsCertDir()
	if err != nil {
		return
	}

	certPEMPath = path.Join(caDir, fmt.Sprintf("%s.pem", name))
	certKeyPath = path.Join(caDir, fmt.Sprintf("%s.key", name))
	return
}

func GetACMEPrivateKeySavePath(email string, ACMEProvider string) (string, error) {
	keyName := fmt.Sprintf("%s_%s.key", email, ACMEProvider)

	saveDir, err := findFile(ACME_PRIVATE_KEY_DIR)
	if err == nil {
		return path.Join(saveDir, keyName), nil
	}

	exec, err := os.Executable()
	if err != nil {
		return "", err
	}
	saveDir = path.Dir(exec)

	saveDir = path.Join(saveDir, ACME_PRIVATE_KEY_DIR)

	if _, err := os.Stat(saveDir); os.IsNotExist(err) {
		err := os.Mkdir(saveDir, 0o755)
		if err != nil {
			return "", fmt.Errorf("cannot create path: %s to save account key: %w", saveDir, err)
		}
	} else if err != nil {
		return "", err
	}

	return path.Join(saveDir, keyName), nil
}

func GetServerCacheSavePath() string {
	cacheFile, err := findFile(SERVER_CACHE_FILE)
	if err == nil {
		return cacheFile
	}

	exec, err := os.Executable()
	if err != nil {
		return SERVER_CACHE_FILE
	}
	saveDir := path.Dir(exec)

	return path.Join(saveDir, SERVER_CACHE_FILE)
}
