package main

import (
	"fmt"
	"os"
	"path/filepath"
	"pkg.para.party/certdx/exec/tools/config"
	"pkg.para.party/certdx/exec/tools/tasks"
	"pkg.para.party/certdx/exec/tools/tasks/txcReplaceCertificate"
)

var (
	buildCommit string
	buildDate   string
)

func main() {
	config.RootCMD.Parse(os.Args[1:])

	if *config.Version {
		fmt.Printf("Certdx tools %s, built at %s\n", buildCommit, buildDate)
		os.Exit(0)
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "show-cache":
			tasks.ShowCache()
		case "google-account":
			tasks.RegisterGoogleAccount()
		case "make-ca":
			tasks.MakeCA()
		case "make-server":
			tasks.MakeServer()
		case "make-client":
			tasks.MakeClient()
		case "tencent-cloud-replace-certificate":
			fallthrough
		case "tencent-cloud-replace-certificates":
			txcReplaceCertificate.TencentCloudReplaceCertificate()
		default:
			if !*config.Help {
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
  show-cache:    						Print server cert cache
  google-account:						Register google cloud ACME account
  make-ca:       						Make grpc mtls CA certificate and key
  make-server:   						Make grpc mtls Server certificate and key
  make-client:   						Make grpc mtls Client certificate and key
  tencent-cloud-replace-certificate:    Replace Tencent Cloud Expiring Certificates

For command details, use %s <commmand> --Help

Options:
%s`,
		executableName, executableName, config.RootCMD.FlagUsages())
}
