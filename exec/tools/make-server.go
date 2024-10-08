package main

import (
	"os"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/tools"
)

func makeServer() {
	var (
		srvCMD = flag.NewFlagSet(os.Args[1], flag.ExitOnError)

		srvDomains      = srvCMD.StringSliceP("dns-names", "d", []string{}, "CertDX grpc server certificate dns names, combine multiple names with \",\"")
		srvOrganization = srvCMD.StringP("organization", "o", "CertDX Private", "Subject Organization")
		srvCommonName   = srvCMD.StringP("common-name", "c", "CertDX Secret Discovery Service", "Subject Common Name")
		srvHelp         = srvCMD.BoolP("help", "h", false, "Print help")
	)
	srvCMD.Parse(os.Args[2:])

	if *srvHelp {
		srvCMD.PrintDefaults()
		os.Exit(0)
	}

	if len(*srvDomains) == 0 {
		logging.Fatal("domains are required")
	}

	err := tools.MakeServerCert(*srvOrganization, *srvCommonName, *srvDomains)
	if err != nil {
		logging.Fatal("err: %s", err)
	}
}
