package kubernetesCertificateUpdater

import (
	"context"
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/logging"
)

func initCmd() (*k8sCertsUpdateCmd, error) {
	if len(os.Args) < 2 {
		return nil, fmt.Errorf("missing subcommand")
	}

	clientCMD := flag.NewFlagSet(os.Args[1], flag.ExitOnError)

	clientHelp := clientCMD.BoolP("help", "h", false, "Print help")
	conf := clientCMD.StringP("conf", "c", "./client.toml", "Certdx client config file path")
	k8sConf := clientCMD.String("k8sConf", "", "Kubeconfig file path (empty: use in-cluster or default kubeconfig resolution)")
	pDebug := clientCMD.BoolP("debug", "d", false, "Enable debug log")

	_ = clientCMD.Parse(os.Args[2:])

	if *clientHelp {
		clientCMD.PrintDefaults()
		os.Exit(0)
	}

	logging.SetDebug(*pDebug)
	if len(*conf) == 0 {
		logging.Error("Config file path is empty")
		return nil, fmt.Errorf("config file path is empty")
	}

	cfg := &k8sCertsUpdateCmd{
		certdxConfig: *conf,
		k8sConfig:    *k8sConf,
	}

	return cfg, nil
}

func KubernetesReplaceCertificate() {
	cmdOpt, err := initCmd()
	if err != nil {
		logging.Fatal("Failed to parse command line: %s", err)
	}

	updater := MakeKubernetesReplaceCertificate(cmdOpt)

	if err := updater.InitCertificateUpdater(); err != nil {
		logging.Fatal("Failed to initialize updating task: %s", err)
	}

	if err := updater.InvokeCertificateUpdate(context.Background()); err != nil {
		logging.Fatal("Failed to update kubernetes certificates: %s", err)
	}
}
