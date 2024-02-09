package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"pkg.para.party/certdx/pkg/client"

	"github.com/BurntSushi/toml"
	flag "github.com/spf13/pflag"
)

var (
	buildCommit string
	buildDate   string
)

var (
	test     = flag.BoolP("test", "t", false, "Testing not verify server certification")
	pLogPath = flag.StringP("log", "l", "", "Log file path")
	help     = flag.BoolP("help", "h", false, "Print help")
	version  = flag.BoolP("version", "v", false, "Print version")
	conf     = flag.StringP("conf", "c", "./client.toml", "Config file path")
)

var certDXDaemon *client.CertDXClientDaemon

func init() {
	log.SetOutput(os.Stderr)
	flag.Parse()
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

	cfile, err := os.Open(*conf)
	if err != nil {
		log.Fatalf("[ERR] Open config file failed: %s", err)
	}
	defer cfile.Close()
	if b, err := io.ReadAll(cfile); err == nil {
		if err := toml.Unmarshal(b, certDXDaemon.Config); err == nil {
			log.Println("[INF] Config loaded")
		} else {
			log.Fatalf("[ERR] Unmarshaling config failed: %s", err)
		}
	} else {
		log.Fatalf("[ERR] Reading config file failed: %s", err)
	}

	if certDXDaemon.Config.Http.MainServer.Url == "" {
		log.Fatalf("[ERR] Main server url should not be empty")
	}

	if len(certDXDaemon.Config.Certifications) == 0 {
		log.Fatalf("[ERR] No certification configured")
	}

	for _, c := range certDXDaemon.Config.Certifications {
		if len(c.Domains) == 0 || c.Name == "" || c.SavePath == "" {
			log.Fatalf("[ERR] Wrong certification configuration")
		}
	}
}

func main() {
	switch certDXDaemon.Config.Server.Mode {
	case "http":
		certDXDaemon.HttpMain()
	default:
		log.Fatalf("[ERR] Mode %s not supported", certDXDaemon.Config.Server.Mode)
	}
}
