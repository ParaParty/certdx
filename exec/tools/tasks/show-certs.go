package tasks

import (
	"fmt"

	"pkg.para.party/certdx/pkg/server"
)

// ShowCerts loads the persisted server cache file and prints its
// contents.
func ShowCerts(name string, args []string) error {
	fs := newFlagSet(name)
	dataDir := registerDataDirFlag(fs)
	help := fs.BoolP("help", "h", false, "Print help")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}

	applyDataDir(*dataDir)

	certStore, err := server.NewCertStore()
	if err != nil {
		return fmt.Errorf("init cert store: %w", err)
	}
	if err := certStore.Load(); err != nil {
		return fmt.Errorf("load cert store: %w", err)
	}
	certStore.PrintCertInfo()
	return nil
}
