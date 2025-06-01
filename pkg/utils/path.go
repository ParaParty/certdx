package utils

import (
	"fmt"
	"os"
	"path"
)

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func MakeSDSCertDir() (string, error) {
	exec, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := path.Dir(exec)

	dir = path.Join(dir, "sds")
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

func GetSDSCAPath() (caPEMPath, caKeyPath string, err error) {
	caDir, err := MakeSDSCertDir()
	if err != nil {
		return
	}

	caPEMPath = path.Join(caDir, "ca.pem")
	caKeyPath = path.Join(caDir, "ca.key")
	return
}

func GetCACounterPath() (caCounterPath string, err error) {
	caDir, err := MakeSDSCertDir()
	if err != nil {
		return
	}

	caCounterPath = path.Join(caDir, "counter.txt")
	return
}

func GetSDSServerCertPath() (certPEMPath, certKeyPath string, err error) {
	caDir, err := MakeSDSCertDir()
	if err != nil {
		return
	}

	certPEMPath = path.Join(caDir, "sds_server.pem")
	certKeyPath = path.Join(caDir, "sds_server.key")
	return
}

func GetSDSClientCertPath(name string) (certPEMPath, certKeyPath string, err error) {
	caDir, err := MakeSDSCertDir()
	if err != nil {
		return
	}

	certPEMPath = path.Join(caDir, fmt.Sprintf("%s.pem", name))
	certKeyPath = path.Join(caDir, fmt.Sprintf("%s.key", name))
	return
}

func GetACMEPrivateKeySavePath(email string, ACMEProvider string) (string, error) {
	exec, err := os.Executable()
	if err != nil {
		return "", err
	}
	saveDir := path.Dir(exec)

	saveDir = path.Join(saveDir, "private")
	keyName := fmt.Sprintf("%s_%s.key", email, ACMEProvider)

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
	exec, err := os.Executable()
	if err != nil {
		return "cache.json"
	}
	saveDir := path.Dir(exec)

	cacheFile := path.Join(saveDir, "cache.json")
	return cacheFile
}
