package config

import (
	"os"

	flag "github.com/spf13/pflag"
)

var (
	RootCMD = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	Help    = RootCMD.BoolP("Help", "h", false, "Print Help")
	Version = RootCMD.BoolP("Version", "v", false, "Print Version")
)
