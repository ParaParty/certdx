package main

import (
	"fmt"
	"os"
	"sync"
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
		logging.Fatal("Invalid config, err: %v", err)
	}

	if err := cdxsrv.Init(); err != nil {
		logging.Fatal("Failed to init certdx server, err: %s", err)
	}
}

func main() {
	errChan := make(chan error, 2)
	var wg sync.WaitGroup

	startServer := func(name string, run func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := run(); err != nil {
				select {
				case errChan <- fmt.Errorf("%s server: %w", name, err):
				default:
				}
			}
		}()
	}

	if cdxsrv.Config.HttpServer.Enabled {
		startServer("http", cdxsrv.HttpSrv)
	}

	if cdxsrv.Config.GRPCSDSServer.Enabled {
		startServer("grpc sds", cdxsrv.SDSSrv)
	}

	if err := cli.WaitForShutdown(func() {
		cdxsrv.Stop()
		wg.Wait()
	}, shutdownTimeout, errChan); err != nil {
		logging.Fatal("%s", err)
	}
}
