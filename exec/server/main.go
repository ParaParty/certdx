package main

import (
	"os"
	"time"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/cli"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/paths"
	"pkg.para.party/certdx/pkg/server"
)

var (
	buildTag  string
	buildDate string
)

const (
	shutdownTimeout = 30 * time.Second
	dataDirEnv      = "CERTDX_DATA_DIR"
)

var (
	pLogPath = flag.StringP("log", "l", "", "Log file path")
	help     = flag.BoolP("help", "h", false, "Print help")
	version  = flag.BoolP("version", "v", false, "Print version")
	pConf    = flag.StringP("conf", "c", "", "Config file path (required)")
	pDebug   = flag.BoolP("debug", "d", false, "Enable debug log")
	pDataDir = flag.String("data-dir", "", "Data directory for mtls/, private/, cache.json (env: "+dataDirEnv+")")
)

var cdxsrv *server.CertDXServer

func init() {
	flag.Parse()

	ver := cli.Version{Name: "server", Tag: buildTag, Date: buildDate}

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

	dataDir := *pDataDir
	if dataDir == "" {
		dataDir = os.Getenv(dataDirEnv)
	}
	if dataDir != "" {
		paths.SetDataDir(dataDir)
	}

	confPath := *pConf
	if confPath == "" {
		logging.Fatal("--conf is required")
	}

	var err error
	cdxsrv, err = server.MakeCertDXServer()
	if err != nil {
		logging.Fatal("%s", err)
	}

	if err := cli.LoadTOML(confPath, &cdxsrv.Config); err != nil {
		logging.Fatal("%s", err)
	}

	if err := cdxsrv.Config.Validate(); err != nil {
		logging.Fatal("Invalid config: %v", err)
	}

	if err := cdxsrv.Init(); err != nil {
		logging.Fatal("Failed to init certdx server: %s", err)
	}
}

func main() {
	if cdxsrv.Config.HttpServer.Enabled {
		go func() {
			if err := cdxsrv.HttpSrv(); err != nil {
				logging.Error("HTTP server failed: %s", err)
				cdxsrv.Stop()
			}
		}()
	}

	if cdxsrv.Config.GRPCSDSServer.Enabled {
		go func() {
			if err := cdxsrv.SDSSrv(); err != nil {
				logging.Error("SDS server failed: %s", err)
				cdxsrv.Stop()
			}
		}()
	}

	// WaitForShutdown handles signal-driven Stop in a goroutine; main
	// blocks on Wait() so subserver-driven Stop also unblocks it.
	go cli.WaitForShutdown(cdxsrv.Stop, shutdownTimeout)
	cdxsrv.Wait()
}
