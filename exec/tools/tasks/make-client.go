package tasks

import (
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/tools"
)

func MakeClient() {
	var (
		clientCMD = flag.NewFlagSet(os.Args[1], flag.ExitOnError)

		clientName         = clientCMD.StringP("name", "n", "", "CertDX grpc client name")
		clientDomains      = clientCMD.StringSliceP("dns-names", "d", []string{}, "CertDX grpc client certificate dns names, combine multiple names with \",\"")
		clientOrganization = clientCMD.StringP("organization", "o", "CertDX Private", "Subject Organization")
		clientCommonName   = clientCMD.StringP("common-name", "c", "CertDX Client: {name}", "Subject Common Name")
		clientHelp         = clientCMD.BoolP("Help", "h", false, "Print Help")
	)
	clientCMD.Parse(os.Args[2:])

	if *clientHelp {
		clientCMD.PrintDefaults()
		os.Exit(0)
	}

	if *clientName == "" {
		logging.Fatal("client name is required")
	}

	if *clientCommonName == "CertDX Client: {name}" {
		*clientCommonName = fmt.Sprintf("CertDX Client: %s", *clientName)
	}

	err := tools.MakeClientCert(*clientName, *clientOrganization, *clientCommonName, *clientDomains)
	if err != nil {
		logging.Fatal("err: %s", err)
	}
}
