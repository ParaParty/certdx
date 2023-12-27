package client

import (
	"certdx/pkg/config"
	"certdx/pkg/types"
	"certdx/pkg/utils"

	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var Config = &config.ClientConfigT{}

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

func requestCert(domains []string) *types.HttpCertResp {
	var resp *types.HttpCertResp
	err := utils.Retry(Config.Server.RetryCount, func() error {
		var err error
		resp, err = GetCert(&Config.Http.MainServer, domains)
		return err
	})
	if err == nil {
		return resp
	}
	log.Printf("[WRN] Failed get cert %v from MainServer: %s", domains, err)

	if Config.Http.StandbyServer.Url != "" {
		err = utils.Retry(Config.Server.RetryCount, func() error {
			var err error
			resp, err = GetCert(&Config.Http.StandbyServer, domains)
			return err
		})
		if err == nil {
			return resp
		}
		log.Printf("[WRN] Failed get cert %v from StandbyServer: %s", domains, err)
	}
	return nil
}

func certWatchDog(cert config.ClientCertification, onChanged ...func(cert, key []byte, c *config.ClientCertification)) {
	var currentCert, currentKey []byte
	sleepTime := 1 * time.Hour // default sleep time
	for {
		log.Printf("[INF] Request cert %v", cert.Domains)
		resp := requestCert(cert.Domains)
		if resp != nil {
			sleepTime = resp.RenewTimeLeft / 4
			if !bytes.Equal(currentCert, resp.Cert) || !bytes.Equal(currentKey, resp.Key) {
				log.Printf("[INF] Notify cert %v changed", cert.Domains)
				currentCert, currentKey = resp.Cert, resp.Key
				for _, handleFunc := range onChanged {
					handleFunc(resp.Cert, resp.Key, &cert)
				}
			} else {
				log.Printf("[INF] Cert %v not changed", cert.Domains)
			}
		}
		t := time.After(sleepTime)
		<-t
	}
}

func writeCertAndDoCommand(cert, key []byte, c *config.ClientCertification) {
	var doCommand, ce, ke bool

	certPath, keyPath := c.GetCertAndKeyPath()
	ce, err := checkFileAndCreate(certPath)
	if err != nil {
		goto ERR
	}
	ke, err = checkFileAndCreate(keyPath)
	if err != nil {
		goto ERR
	}
	// if cert file is firstly created, don't do reload command
	doCommand = ce && ke

	err = os.WriteFile(certPath, cert, 0o777)
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
			log.Printf("[ERR] Failed executing command %s: %s", c.ReloadCommand, err)
		}
	}
	return
ERR:
	log.Printf("[ERR] Failed save cert file: %s", err)
}

func HttpMain() {
	for index, c := range Config.Certifications {
		go certWatchDog(c, writeCertAndDoCommand)
		if index != len(Config.Certifications)-1 {
			t := time.After(1 * time.Second)
			<-t
		}
	}
	blockingChan := make(chan struct{})
	<-blockingChan
}
