package tasks

import (
	"fmt"
	"strings"

	"pkg.para.party/certdx/pkg/paths"
	"pkg.para.party/certdx/pkg/tools"
)

// commonNameTemplate is the placeholder substituted with the client
// name when the user does not override --common-name.
const commonNameTemplate = "CertDX Client: {name}"

// MakeClient generates a client certificate signed by the certdx CA.
func MakeClient(name string, args []string) error {
	fs := newFlagSet(name)
	var (
		clientName = fs.StringP("name", "n", "", "CertDX grpc client name")
		domains    = fs.StringSliceP("dns-names", "d", []string{}, "Client certificate DNS names (comma-separated)")
		org        = fs.StringP("organization", "o", "CertDX Private", "Subject Organization")
		commonName = fs.StringP("common-name", "c", commonNameTemplate, "Subject Common Name")
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

	if *clientName == "" {
		return fmt.Errorf("--name is required")
	}
	cn := strings.ReplaceAll(*commonName, "{name}", *clientName)

	paths.SetMtlsDir(*mtlsDir)

	if err := tools.MakeClientCert(*clientName, *org, cn, *domains); err != nil {
		return fmt.Errorf("create client cert: %w", err)
	}
	return nil
}
