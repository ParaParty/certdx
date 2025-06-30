package txcCertificateUpdater

import (
	"fmt"
	flag "github.com/spf13/pflag"
	"os"
	"pkg.para.party/certdx/pkg/logging"
)

func initCmd() (*txcCertsUpdateCmd, error) {
	var (
		clientCMD = flag.NewFlagSet(os.Args[1], flag.ExitOnError)

		clientHelp = clientCMD.BoolP("help", "h", false, "Print help")
		conf       = clientCMD.StringP("conf", "c", "./client.toml", "Config file path")
		pDebug     = clientCMD.BoolP("debug", "d", false, "Enable debug log")
	)
	_ = clientCMD.Parse(os.Args[2:])

	if *clientHelp {
		clientCMD.PrintDefaults()
		os.Exit(0)
	}

	logging.SetDebug(*pDebug)
	if conf == nil || len(*conf) == 0 {
		logging.Error("Config file path is empty")
		return nil, fmt.Errorf("config file path is empty")
	}

	cfg := &txcCertsUpdateCmd{
		confPath: conf,
	}

	return cfg, nil
}

func TencentCloudReplaceCertificate() {
	// init
	cmdOpt, err := initCmd()
	if err != nil {
		logging.Fatal("Failed to initialize certdx: %s", err)
	}

	updater := MakeTencentCloudCertificateUpdater(cmdOpt)

	err = updater.InitCertificateUpdater()
	if err != nil {
		logging.Fatal("Failed to initialize updating task: %s", err)
	}

	err = updater.InvokeCertificateUpdate()
	if err != nil {
		logging.Fatal("Failed to initialize tencent cloud: %s", err)
	}
}
