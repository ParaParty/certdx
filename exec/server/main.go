package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/acme"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/server"
)

var (
	buildCommit string
	buildDate   string
)

var (
	pLogPath = flag.StringP("log", "l", "", "Log file path")
	help     = flag.BoolP("help", "h", false, "Print help")
	version  = flag.BoolP("version", "v", false, "Print version")
	pConf    = flag.StringP("conf", "c", "./server.toml", "Config file path")
	pDebug   = flag.BoolP("debug", "d", false, "Enable debug log")
)

var config = server.Config

func init() {
	flag.Parse()
	logging.SetLogFile(*pLogPath)
	logging.SetDebug(*pDebug)

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *version {
		fmt.Printf("Certdx server %s, built at %s\n", buildCommit, buildDate)
		os.Exit(0)
	}

	config.SetDefault()
	cfile, err := os.Open(*pConf)
	if err != nil {
		logging.Fatal("Open config file failed, err: %s", err)
	}
	defer cfile.Close()
	if b, err := io.ReadAll(cfile); err == nil {
		if err := toml.Unmarshal(b, config); err == nil {
			logging.Info("Config loaded")
		} else {
			logging.Fatal("Unmarshaling config failed, err: %s", err)
		}
	} else {
		logging.Fatal("Reading config file failed, err: %s", err)
	}

	if !acme.ACMEProviderSupported(config.ACME.Provider) {
		logging.Fatal("ACME provider not supported: %s", config.ACME.Provider)
	}

	d, err := time.ParseDuration(config.ACME.CertLifeTime)
	if err != nil {
		logging.Fatal("Invalid config, err: %s", err)
	}
	config.ACME.CertLifeTimeDuration = d

	d, err = time.ParseDuration(config.ACME.RenewTimeLeft)
	if err != nil {
		logging.Fatal("Invalid config, err: %s", err)
	}
	config.ACME.RenewTimeLeftDuration = d

	if err = config.Validate(); err != nil {
		logging.Fatal("Invalid config, err: %v", err)
	}

	if err := acme.InitACME(config); err != nil {
		logging.Fatal("Failed to init ACME client, err: %s", err)
	}

	server.InitCache()
}

func main() {
	if config.HttpServer.Enabled {
		go server.HttpSrv()
	}

	stopSDS := make(chan struct{}, 1)
	if config.GRPCSDSServer.Enabled {
		go server.SDSSrv(stopSDS)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop

	go func() {
		<-stop
		logging.Fatal("Fast dying...")
	}()

	if config.GRPCSDSServer.Enabled {
		stopSDS <- struct{}{}
	}
}
