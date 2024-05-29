package server

import (
	"fmt"
	"os"
	"path"
)

func getPrivateKeySavePath(email string, ACMEProvider string) (string, error) {
	saveDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	saveDir = path.Join(saveDir, "private")
	keyName := fmt.Sprintf("%s_%s.key", email, ACMEProvider)

	if _, err := os.Stat(saveDir); os.IsNotExist(err) {
		err := os.Mkdir(saveDir, 0o600)
		if err != nil {
			return "", fmt.Errorf("cannot create path: %s to save account key: %w", saveDir, err)
		}
	} else if err != nil {
		return "", err
	}

	return path.Join(saveDir, keyName), nil
}

func getCacheSavePath() (cachePath string, exist bool) {
	saveDir, err := os.Getwd()
	if err != nil {
		return "", false
	}

	cacheFile := path.Join(saveDir, "cache.json")
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return cacheFile, false
	} else if err != nil {
		return "", false
	}

	return cacheFile, true
}
