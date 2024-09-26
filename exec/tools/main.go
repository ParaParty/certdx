package main

import (
	"fmt"
	"os"
	"path/filepath"

	flag "github.com/spf13/pflag"
	"pkg.para.party/certdx/pkg/logging"
)

var (
	buildCommit string
	buildDate   string
)

var (
	rootCMD = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	help    = rootCMD.BoolP("help", "h", false, "Print help")
	version = rootCMD.BoolP("version", "v", false, "Print version")
)

func main() {
	rootCMD.Parse(os.Args[1:])
	logging.LogInit("")

	if *version {
		fmt.Printf("Certdx tools %s, built at %s\n", buildCommit, buildDate)
		os.Exit(0)
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "google-account":
			registerGoogleAccount()
		case "make-ca":
			makeCA()
		case "make-server":
			makeServer()
		case "make-client":
			makeClient()
		default:
			if !*help {
				fmt.Printf("Unknown command: %s", os.Args[1])
			}
			printHelp()
		}
	} else {
		printHelp()
	}
}

func printHelp() {
	executableName := filepath.Base(os.Args[0])
	fmt.Printf(`
Certdx tools

Usage:
  %s <command> [options]

Commands:
  google-account: Register google cloud ACME account
  make-ca:        Make grpc mtls CA certificate and key
  make-server:    Make grpc mtls Server certificate and key
  make-client:    Make grpc mtls Client certificate and key

For command details, use %s <commmand> --help

Options:
%s`,
		executableName, executableName, rootCMD.FlagUsages())
}
