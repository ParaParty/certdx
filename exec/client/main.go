package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/client"
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
	logging.LogInit(*pLogPath)
	logging.SetDebug(*pDebug)

	certDXDaemon = client.MakeCertDXClientDaemon()

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *version {
		fmt.Printf("Certdx client %s, built at %s\n", buildCommit, buildDate)
		os.Exit(0)
	}

	if *test {
		certDXDaemon.ClientOpt = append(certDXDaemon.ClientOpt, client.WithCertDXInsecure())
	}

	cfile, err := os.Open(*conf)
	if err != nil {
		logging.Fatal("Open config file failed, err: %s", err)
	}
	defer cfile.Close()
	if b, err := io.ReadAll(cfile); err == nil {
		if err := toml.Unmarshal(b, certDXDaemon.Config); err == nil {
			logging.Info("Config loaded")
		} else {
			logging.Fatal("Unmarshaling config failed, err: %s", err)
		}
	} else {
		logging.Fatal("Reading config file failed, err: %s", err)
	}

	certDXDaemon.Config.Common.ReconnectDuration, err = time.ParseDuration(certDXDaemon.Config.Common.ReconnectInterval)
	if err != nil {
		logging.Fatal("Failed to parse interval, err: %s", err)
	}

	if len(certDXDaemon.Config.Certifications) == 0 {
		logging.Fatal("No certification configured")
	}

	for _, c := range certDXDaemon.Config.Certifications {
		if len(c.Domains) == 0 || c.Name == "" || c.SavePath == "" {
			logging.Fatal("Wrong certification configuration")
		}
	}

	certDXDaemon.ClientInit()
}

func main() {
	switch certDXDaemon.Config.Common.Mode {
	case "http":
		if certDXDaemon.Config.Http.MainServer.Url == "" {
			logging.Fatal("Http main server url should not be empty")
		}
		certDXDaemon.HttpMain()
	case "grpc":
		if certDXDaemon.Config.GRPC.MainServer.Server == "" {
			logging.Fatal("GRPC main server url should not be empty")
		}
		certDXDaemon.GRPCMain()
	default:
		logging.Fatal("Mode: \"%s\" is not supported", certDXDaemon.Config.Common.Mode)
	}
}
