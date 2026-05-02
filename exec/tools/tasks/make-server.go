package tasks

import (
	"fmt"

	"pkg.para.party/certdx/pkg/paths"
	"pkg.para.party/certdx/pkg/tools"
)

// MakeServer generates a server certificate signed by the certdx CA.
func MakeServer(name string, args []string) error {
	fs := newFlagSet(name)
	var (
		domains    = fs.StringSliceP("dns-names", "d", []string{}, "Server certificate DNS names (comma-separated)")
		org        = fs.StringP("organization", "o", "CertDX Private", "Subject Organization")
		commonName = fs.StringP("common-name", "c", "CertDX Secret Discovery Service", "Subject Common Name")
		mtlsDir    = fs.String("mtls-dir", "", "mTLS material directory")
		help       = fs.BoolP("help", "h", false, "Print help")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}

	if len(*domains) == 0 {
		return fmt.Errorf("--dns-names is required")
	}

	paths.SetMtlsDir(*mtlsDir)

	if err := tools.MakeServerCert(*org, *commonName, *domains); err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}
	return nil
}
