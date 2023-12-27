package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"pkg.para.party/certdx/pkg/server"
	"time"

	"github.com/BurntSushi/toml"
	flag "github.com/spf13/pflag"
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

var (
	config    = server.Config
	certCache = server.ServerCertCache
)

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

	if config.Cloudflare.APIKey == "" || config.Cloudflare.Email == "" ||
		len(config.ACME.AllowedDomains) == 0 || (config.HttpServer.Secure &&
		len(config.HttpServer.Names) == 0) {

		log.Fatalln("[ERR] Invalid config")
	}

	if err := server.InitACMEAccount(); err != nil {
		log.Fatalf("[ERR] Failed init ACME account: %s", err)
	}
}

func serveHttps() {
	entry := certCache.GetEntry(config.HttpServer.Names)
	// when starting up, no cert is listening, just start a watch dog anyway
	go entry.CertWatchDog()
	<-*entry.Updated.Load()

	for {
		cert := entry.Cert()
		certificate, err := tls.X509KeyPair(cert.Cert, cert.Key)
		if err != nil {
			log.Fatalf("[ERR] Failed to load cert: %s", err)
		}

		server := http.Server{
			Addr: config.HttpServer.Listen,
		}

		server.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		}

		go func() {
			log.Printf("[INF] Https server started")
			err := server.ListenAndServe()
			log.Printf("[INF] Https server stopped: %s", err)
		}()
		<-*entry.Updated.Load()
		server.Close()
	}
}

func main() {
	if config.HttpServer.Enabled {
		http.HandleFunc(config.HttpServer.APIPath, server.APIHandler)

		if !config.HttpServer.Secure {
			log.Printf("[INF] Http server started")
			http.ListenAndServe(config.HttpServer.Listen, nil)
		} else {
			serveHttps()
		}
	}
}
