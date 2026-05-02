package tasks

import (
	"fmt"

	"pkg.para.party/certdx/pkg/server"
)

// ShowCache loads the persisted server cache file and prints its
// contents.
func ShowCache(name string, args []string) error {
	fs := newFlagSet(name)
	help := fs.BoolP("help", "h", false, "Print help")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}

	cacheFile := server.MakeServerCacheFile()
	if err := cacheFile.ReadCacheFile(); err != nil {
		return fmt.Errorf("read cache file: %w", err)
	}
	cacheFile.PrintCertInfo()
	return nil
}
