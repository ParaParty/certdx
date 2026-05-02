package kubernetesCertificateUpdater

import (
	"context"
	"fmt"

	flag "github.com/spf13/pflag"

	"pkg.para.party/certdx/pkg/logging"
)

// KubernetesReplaceCertificate is the entrypoint for the
// kubernetes-certificate-updater sub-command.
func KubernetesReplaceCertificate(name string, args []string) error {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		help    = fs.BoolP("help", "h", false, "Print help")
		conf    = fs.StringP("conf", "c", "./client.toml", "Certdx client config file path")
		k8sConf = fs.String("k8sConf", "", "Kubeconfig file path (empty: use in-cluster or default kubeconfig resolution)")
		debug   = fs.BoolP("debug", "d", false, "Enable debug log")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}

	if *conf == "" {
		return fmt.Errorf("--conf is required")
	}

	logging.SetDebug(*debug)

	cmdOpt := &k8sCertsUpdateCmd{
		certdxConfig: *conf,
		k8sConfig:    *k8sConf,
	}

	updater := MakeKubernetesReplaceCertificate(cmdOpt)

	if err := updater.InitCertificateUpdater(); err != nil {
		return fmt.Errorf("init updater: %w", err)
	}

	if err := updater.InvokeCertificateUpdate(context.Background()); err != nil {
		return fmt.Errorf("update kubernetes certificates: %w", err)
	}
	return nil
}
