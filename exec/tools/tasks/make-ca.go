package tasks

import (
	"fmt"

	"pkg.para.party/certdx/pkg/tools"
)

// MakeCA generates a fresh certdx CA certificate and key pair under the
// resolved mtls directory.
func MakeCA(name string, args []string) error {
	fs := newFlagSet(name)
	var (
		org        = fs.StringP("organization", "o", "CertDX Private", "Subject Organization")
		commonName = fs.StringP("common-name", "c", "CertDX Private Certificate Authority", "Subject Common Name")
		validFor   = fs.Duration("valid-for", tools.DefaultCALifetime, "Certificate validity period")
		dataDir    = registerDataDirFlag(fs)
		help       = fs.BoolP("help", "h", false, "Print help")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}

	// tools.WithLifetime silently keeps the default for a non-positive
	// duration, which would hide a typo like "--valid-for -1h" or
	// "--valid-for 0". Reject it here instead.
	if *validFor <= 0 {
		return fmt.Errorf("--valid-for must be positive, got %s", *validFor)
	}

	applyDataDir(*dataDir)

	if err := tools.MakeCA(*org, *commonName, tools.WithLifetime(*validFor)); err != nil {
		return fmt.Errorf("create CA: %w", err)
	}
	return nil
}
