package txcCertificateUpdater

import (
	"context"
	"fmt"

	flag "github.com/spf13/pflag"

	"pkg.para.party/certdx/pkg/logging"
)

// TencentCloudReplaceCertificate is the entrypoint for the
// tencent-cloud-certificate-updater sub-command.
func TencentCloudReplaceCertificate(name string, args []string) error {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	var (
		help     = fs.BoolP("help", "h", false, "Print help")
		confPath = fs.StringP("conf", "c", "./client.toml", "Config file path")
		debug    = fs.BoolP("debug", "d", false, "Enable debug log")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}
	if *confPath == "" {
		return fmt.Errorf("--conf is required")
	}

	logging.SetDebug(*debug)

	cmd := &txcCertsUpdateCmd{confPath: confPath}
	updater := MakeTencentCloudCertificateUpdater(cmd)

	if err := updater.InitCertificateUpdater(); err != nil {
		return fmt.Errorf("init updater: %w", err)
	}
	if err := updater.InvokeCertificateUpdate(context.Background()); err != nil {
		return fmt.Errorf("update certificates: %w", err)
	}
	return nil
}
