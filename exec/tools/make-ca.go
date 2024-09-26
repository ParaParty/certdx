package main

import (
	"os"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/logging"
	"pkg.para.party/certdx/pkg/tools"
)

func makeCA() {
	var (
		caCMD = flag.NewFlagSet(os.Args[1], flag.ExitOnError)

		caOrganization = caCMD.StringP("organization", "o", "CertDX Private", "Subject Organization")
		caCommonName   = caCMD.StringP("common-name", "c", "CertDX Private Certificate Authority", "Subject Common Name")
		caHelp         = caCMD.BoolP("help", "h", false, "Print help")
	)
	caCMD.Parse(os.Args[2:])

	if *caHelp {
		caCMD.PrintDefaults()
		os.Exit(0)
	}

	err := tools.MakeCA(*caOrganization, *caCommonName)
	if err != nil {
		logging.Fatal("err: %s", err)
	}
}
