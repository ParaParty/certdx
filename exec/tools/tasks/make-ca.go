package tasks

import (
	"fmt"

	"pkg.para.party/certdx/pkg/paths"
	"pkg.para.party/certdx/pkg/tools"
)

// MakeCA generates a fresh certdx CA certificate and key pair under the
// resolved mtls directory.
func MakeCA(name string, args []string) error {
	fs := newFlagSet(name)
	var (
		org        = fs.StringP("organization", "o", "CertDX Private", "Subject Organization")
		commonName = fs.StringP("common-name", "c", "CertDX Private Certificate Authority", "Subject Common Name")
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

	paths.SetMtlsDir(*mtlsDir)

	if err := tools.MakeCA(*org, *commonName); err != nil {
		return fmt.Errorf("create CA: %w", err)
	}
	return nil
}
