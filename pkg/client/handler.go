package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
)

type CertificateUpdateHandler func(fullchain, key []byte, c *config.ClientCertification)

func checkFileAndCreate(file string) (exists bool, err error) {
	exists = false
	if _, err = os.Stat(file); os.IsNotExist(err) {
		dir := filepath.Dir(file)
		if _, err = os.Stat(dir); os.IsNotExist(err) {
			err = os.MkdirAll(dir, 0o777)
			if err != nil {
				return
			}
		} else if err != nil {
			return
		}

		err = os.WriteFile(file, []byte{}, 0o777)
		if err != nil {
			return
		}
		return
	} else if err != nil {
		return
	}

	exists = true
	return
}

func writeCertAndDoCommand(fullchain, key []byte, c *config.ClientCertification) {
	var doCommand, ce, ke bool

	certPath, keyPath, err := c.GetFullChainAndKeyPath()
	if err != nil {
		logging.Debug("Failed to get full chain and key path")
		return
	}
	ce, err = checkFileAndCreate(certPath)
	if err != nil {
		goto ERR
	}
	ke, err = checkFileAndCreate(keyPath)
	if err != nil {
		goto ERR
	}
	// if cert file is firstly created, don't do reload command
	doCommand = ce && ke

	err = os.WriteFile(certPath, fullchain, 0o777)
	if err != nil {
		goto ERR
	}
	err = os.WriteFile(keyPath, key, 0o777)
	if err != nil {
		goto ERR
	}
	if doCommand && c.ReloadCommand != "" {
		args := strings.Fields(c.ReloadCommand)
		err := exec.Command(args[0], args[1:]...).Run()
		if err != nil {
			logging.Error("Failed executing command %s, err: %s", c.ReloadCommand, err)
		}
	}
	return
ERR:
	logging.Error("Failed to save cert file, err: %s", err)
}
