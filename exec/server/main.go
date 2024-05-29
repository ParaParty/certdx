package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	flag "github.com/spf13/pflag"
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
)

var config = server.Config

func init() {
	log.SetOutput(os.Stderr)
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *version {
		fmt.Printf("Certdx server %s, built at %s\n", buildCommit, buildDate)
		os.Exit(0)
	}

	if *pLogPath != "" {
		logFile, err := os.OpenFile(*pLogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, os.ModePerm)
		if err != nil {
			log.Printf("[ERR] Failed to open log file %s : %s", *pLogPath, err)
			os.Exit(1)
		}
		log.Printf("[INF] Log to file: %s", *pLogPath)
		mw := io.MultiWriter(os.Stderr, logFile)
		log.SetOutput(mw)
	}

	config.SetDefault()
	cfile, err := os.Open(*pConf)
	if err != nil {
		log.Fatalf("[ERR] Open config file failed: %s", err)
	}
	defer cfile.Close()
	if b, err := io.ReadAll(cfile); err == nil {
		if err := toml.Unmarshal(b, config); err == nil {
			log.Println("[INF] Config loaded")
		} else {
			log.Fatalf("[ERR] Unmarshaling config failed: %s", err)
		}
	} else {
		log.Fatalf("[ERR] Reading config file failed: %s", err)
	}

	if !server.ACMEProviderSupported(config.ACME.Provider) {
		log.Fatalf("[ERR] ACME provider not supported: %s", config.ACME.Provider)
	}

	d, err := time.ParseDuration(config.ACME.CertLifeTime)
	if err != nil {
		log.Fatalf("[ERR] Invalid config: %s", err)
	}
	config.ACME.CertLifeTimeDuration = d

	d, err = time.ParseDuration(config.ACME.RenewTimeLeft)
	if err != nil {
		log.Fatalf("[ERR] Invalid config: %s", err)
	}
	config.ACME.RenewTimeLeftDuration = d

	if err = config.Validate(); err != nil {
		log.Fatalf("[ERR] Invalid config, %v\n", err)
	}

	if err := server.InitACMEAccount(); err != nil {
		log.Fatalf("[ERR] Failed init ACME account: %s", err)
	}

	server.InitCache()
}

func main() {
	if config.HttpServer.Enabled {
		server.HttpSrv()
	}
}
