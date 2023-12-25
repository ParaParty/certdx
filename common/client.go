package common

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

func (c *ClientCertification) getCertAndKeyPath() (cert, key string) {
	cert = path.Join(c.SavePath, fmt.Sprintf("%s.pem", c.Name))
	key = path.Join(c.SavePath, fmt.Sprintf("%s.key", c.Name))
	return
}

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

func requestCert(domains []string) *httpCertResp {
	var resp *httpCertResp
	err := retry(ClientConfig.Server.RetryCount, func() error {
		var err error
		resp, err = HttpGetCert(&ClientConfig.Http.MainServer, domains)
		return err
	})
	if err == nil {
		return resp
	}
	log.Printf("[WRN] Failed get cert %v from MainServer: %s", domains, err)

	if ClientConfig.Http.StandbyServer.Url != "" {
		err = retry(ClientConfig.Server.RetryCount, func() error {
			var err error
			resp, err = HttpGetCert(&ClientConfig.Http.StandbyServer, domains)
			return err
		})
		if err == nil {
			return resp
		}
		log.Printf("[WRN] Failed get cert %v from StandbyServer: %s", domains, err)
	}
	return nil
}

func clientCertWatchDog(cert ClientCertification, onChanged ...func(cert, key []byte, c *ClientCertification)) {
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

func clientWriteCertAndDoCommand(cert, key []byte, c *ClientCertification) {
	var doCommand, ce, ke bool

	certPath, keyPath := c.getCertAndKeyPath()
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

func ClientHttpMain() {
	for index, c := range ClientConfig.Certifications {
		go clientCertWatchDog(c, clientWriteCertAndDoCommand)
		if index != len(ClientConfig.Certifications)-1 {
			t := time.After(1 * time.Second)
			<-t
		}
	}
	blockingChan := make(chan struct{})
	<-blockingChan
}
