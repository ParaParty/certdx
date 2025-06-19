package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
)

var (
	buildCommit string
	buildDate   string
)

var (
	test     = flag.BoolP("test", "t", false, "Test mode: skip http server certificate verification")
	pLogPath = flag.StringP("log", "l", "", "Log file path")
	help     = flag.BoolP("help", "h", false, "Print help")
	version  = flag.BoolP("version", "v", false, "Print version")
	conf     = flag.StringP("conf", "c", "./client.toml", "Config file path")
	pDebug   = flag.BoolP("debug", "d", false, "Enable debug log")
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

	logging.SetLogFile(*pLogPath)
	logging.SetDebug(*pDebug)
	logging.Info("\nStarting certdx client %s, built at %s", buildCommit, buildDate)

	certDXDaemon = client.MakeCertDXClientDaemon()

	if *test {
		certDXDaemon.ClientOpt = append(certDXDaemon.ClientOpt, client.WithCertDXInsecure())
	}

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

	go func() {
		<-signalChan
		certDXDaemon.Stop()

		// TODO remove this feature later? Graceful stop is fast enough maybe...
		<-signalChan
		logging.Fatal("Fast dying...")
	}()

	switch certDXDaemon.Config.Common.Mode {
	case config.CLIENT_MODE_HTTP:
		certDXDaemon.HttpMain()
	case config.CLIENT_MODE_GRPC:
		certDXDaemon.GRPCMain()
	default:
		logging.Fatal("Mode: \"%s\" is not supported", certDXDaemon.Config.Common.Mode)
	}
}
