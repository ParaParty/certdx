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

	if err := cli.LoadTOML(*pConf, &cdxsrv.Config); err != nil {
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
