package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/logging"
)

var (
	conf   = flag.StringP("conf", "c", "./client.toml", "Config file path")
	pDebug = flag.BoolP("debug", "d", false, "Enable debug log")
)

var certDXDaemon *client.CertDXClientDaemon

func init() {
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *version {
		fmt.Printf("Certdx client %s, built at %s\n", buildCommit, buildDate)
		os.Exit(0)
	}

	logging.SetDebug(*pDebug)
	logging.Info("\nStarting certdx client %s, built at %s", buildCommit, buildDate)

	certDXDaemon = client.MakeCertDXClientDaemon()
	err := certDXDaemon.LoadConfigurationAndValidate(*conf)
	if err != nil {
		logging.Fatal("Invalid config: %s", err)
	}
	logging.Debug("Reconnect duration is: %s", certDXDaemon.Config.Common.ReconnectDuration)

	certDXDaemon.ClientInit()
}

func main() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	//certDXDaemon.GetCertificate()
}
