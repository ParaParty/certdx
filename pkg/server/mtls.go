package server

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/utils"
)

func getMtlsConfig() *tls.Config {
	srvCertPath, srvKeyPath, err := utils.GetMtlsServerCertPath()
	if err != nil {
		logging.Fatal("err: %s", err)
	}

	cert, err := tls.LoadX509KeyPair(srvCertPath, srvKeyPath)
	if err != nil {
		logging.Fatal("Invalid server cert, err: %s", err)
	}

	caPEMPath, _, err := utils.GetMtlsCAPath()
	if err != nil {
		logging.Fatal("%s", err)
	}
	caPEM, err := os.ReadFile(caPEMPath)
	if err != nil {
		logging.Fatal("err: %s", err)
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(caPEM) {
		logging.Fatal("Invalid ca cert")
	}

	return &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    capool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}
