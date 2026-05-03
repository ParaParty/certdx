package tasks

import (
	"fmt"

	"pkg.para.party/certdx/pkg/server"
)

// ShowCerts loads the persisted server cache file and prints its
// contents.
func ShowCerts(name string, args []string) error {
	fs := newFlagSet(name)
	help := fs.BoolP("help", "h", false, "Print help")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}

	certStore := server.NewCertStore()
	if err := certStore.Load(); err != nil {
		return fmt.Errorf("load cert store: %w", err)
	}
	certStore.PrintCertInfo()
	return nil
}
