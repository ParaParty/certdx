package main

import (
	"os"
	"time"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/cli"
	"pkg.para.party/certdx/pkg/client"
	"pkg.para.party/certdx/pkg/config"
	"pkg.para.party/certdx/pkg/logging"
)

var (
	buildCommit string
	buildDate   string
)

const shutdownTimeout = 30 * time.Second

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

	ver := cli.Version{Name: "client", Commit: buildCommit, Date: buildDate}

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *version {
		ver.Print()
		os.Exit(0)
	}

	cli.Bootstrap(cli.LogConfig{Path: *pLogPath, Debug: *pDebug})
	logging.Info("\nStarting %s", ver)

	certDXDaemon = client.MakeCertDXClientDaemon()
	if *test {
		certDXDaemon.ClientOpt = append(certDXDaemon.ClientOpt, client.WithCertDXInsecure())
	}

	if err := certDXDaemon.LoadConfigurationAndValidate(*conf); err != nil {
		logging.Fatal("Invalid config: %s", err)
	}
	logging.Debug("Reconnect duration is: %s", certDXDaemon.Config.Common.ReconnectDuration)

	certDXDaemon.ClientInit()
}

func main() {
	go cli.WaitForShutdown(certDXDaemon.Stop, shutdownTimeout)

	var err error
	switch certDXDaemon.Config.Common.Mode {
	case config.CLIENT_MODE_HTTP:
		err = certDXDaemon.HttpMain()
	case config.CLIENT_MODE_GRPC:
		err = certDXDaemon.GRPCMain()
	default:
		logging.Fatal("Mode: \"%s\" is not supported", certDXDaemon.Config.Common.Mode)
	}
	if err != nil {
		logging.Fatal("Daemon exited with error: %s", err)
	}
}
