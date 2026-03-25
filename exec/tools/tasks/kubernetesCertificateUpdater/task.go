package kubernetesCertificateUpdater

import (
	"context"
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/logging"
)

func initCmd() (*k8sCertsUpdateCmd, error) {
	var (
		clientCMD = flag.NewFlagSet(os.Args[1], flag.ExitOnError)

		clientHelp = clientCMD.BoolP("help", "h", false, "Print help")
		conf       = clientCMD.StringP("conf", "c", "./client.toml", "Config file path")
		k8sConf    = clientCMD.StringP("k8sConf", "", "", "Config file path")
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
	if k8sConf == nil || len(*k8sConf) == 0 {
		emptyStr := ""
		k8sConf = &emptyStr
	}

	cfg := &k8sCertsUpdateCmd{
		certdxConfig: conf,
		k8sConfig:    k8sConf,
	}

	return cfg, nil
}

func KubernetesReplaceCertificate() {
	// init
	cmdOpt, err := initCmd()
	if err != nil {
		logging.Fatal("Failed to initialize certdx: %s", err)
	}

	updater := MakeKubernetesReplaceCertificate(cmdOpt)

	err = updater.InitCertificateUpdater()
	if err != nil {
		logging.Fatal("Failed to initialize updating task: %s", err)
	}

	err = updater.InvokeCertificateUpdate(context.Background())
	if err != nil {
		logging.Fatal("Failed to initialize tencent cloud: %s", err)
	}
}
