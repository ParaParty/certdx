package main

import (
	"io"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/cli"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/paths"
	"pkg.para.party/certdx/pkg/server"
)

var (
	buildCommit string
	buildDate   string
)

const shutdownTimeout = 30 * time.Second

var (
	pLogPath = flag.StringP("log", "l", "", "Log file path")
	help     = flag.BoolP("help", "h", false, "Print help")
	version  = flag.BoolP("version", "v", false, "Print version")
	pConf    = flag.StringP("conf", "c", "./server.toml", "Config file path")
	pDebug   = flag.BoolP("debug", "d", false, "Enable debug log")
	pMtlsDir = flag.String("mtls-dir", "", "mTLS material directory")
)

var cdxsrv *server.CertDXServer

func init() {
	flag.Parse()

	ver := cli.Version{Name: "server", Commit: buildCommit, Date: buildDate}

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

	paths.SetMtlsDir(*pMtlsDir)

	cdxsrv = server.MakeCertDXServer()

	cfile, err := os.Open(*pConf)
	if err != nil {
		logging.Fatal("Open config file failed, err: %s", err)
	}
	defer cfile.Close()
	if b, err := io.ReadAll(cfile); err == nil {
		if err := toml.Unmarshal(b, &cdxsrv.Config); err == nil {
			logging.Info("Config loaded")
		} else {
			logging.Fatal("Unmarshaling config failed, err: %s", err)
		}
	} else {
		logging.Fatal("Reading config file failed, err: %s", err)
	}

	if err = cdxsrv.Config.Validate(); err != nil {
		logging.Fatal("Invalid config, err: %v", err)
	}

	if err := cdxsrv.Init(); err != nil {
		logging.Fatal("Failed to init certdx server, err: %s", err)
	}
}

func main() {
	if cdxsrv.Config.HttpServer.Enabled {
		go cdxsrv.HttpSrv()
	}

	if cdxsrv.Config.GRPCSDSServer.Enabled {
		go cdxsrv.SDSSrv()
	}

	cli.WaitForShutdown(cdxsrv.Stop, shutdownTimeout)
}
