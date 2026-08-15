package txcCertificateUpdater

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

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

	// The run is bounded so an unreachable or rejecting Tencent Cloud
	// endpoint exits nonzero for cron alerting instead of hanging, and a
	// SIGINT/SIGTERM cancels the in-flight API calls.
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(ctx, waitDeadline)
	defer cancel()

	if err := updater.InvokeCertificateUpdate(ctx); err != nil {
		return fmt.Errorf("update certificates: %w", err)
	}
	return nil
}
