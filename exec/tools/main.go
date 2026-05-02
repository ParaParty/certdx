package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"pkg.para.party/certdx/exec/tools/tasks"
	"pkg.para.party/certdx/exec/tools/tasks/kubernetesCertificateUpdater"
	"pkg.para.party/certdx/exec/tools/tasks/txcCertificateUpdater"
)

// Populated via -ldflags at build time.
var (
	buildCommit string
	buildDate   string
)

// taskFunc is the shared signature implemented by every sub-command.
type taskFunc func(name string, args []string) error

// command bundles a task with its short help line. An empty `help`
// hides the entry from the auto-generated help output, which is how
// short and legacy aliases share a handler with their canonical name
// without doubling up the listing.
type command struct {
	run  taskFunc
	help string
}

// commands is the registry of sub-commands. Canonical names carry a
// non-empty `help`; alias names point at the same `run` with `help: ""`.
var commands = map[string]command{
	"show-cache":                         {tasks.ShowCache, "Print server cert cache"},
	"google-account":                     {tasks.RegisterGoogleAccount, "Register Google ACME account"},
	"make-ca":                            {tasks.MakeCA, "Make grpc mtls CA certificate and key"},
	"make-server":                        {tasks.MakeServer, "Make grpc mtls server certificate and key"},
	"make-client":                        {tasks.MakeClient, "Make grpc mtls client certificate and key"},
	"tencent-cloud-certificate-updater":  {txcCertificateUpdater.TencentCloudReplaceCertificate, "Replace Tencent Cloud expiring certificates"},
	"tencent-cloud-certificates-updater": {txcCertificateUpdater.TencentCloudReplaceCertificate, ""},
	"tx-update":                          {txcCertificateUpdater.TencentCloudReplaceCertificate, ""},
	"kubernetes-certificate-updater":     {kubernetesCertificateUpdater.KubernetesReplaceCertificate, "Patch annotated Kubernetes TLS secrets"},
	"k8s-certificate-updater":            {kubernetesCertificateUpdater.KubernetesReplaceCertificate, ""},
	"k8s-update":                         {kubernetesCertificateUpdater.KubernetesReplaceCertificate, ""},
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printHelp()
		return
	}

	switch args[0] {
	case "-v", "--version":
		fmt.Printf("Certdx tools %s, built at %s\n", buildCommit, buildDate)
		return
	case "-h", "--help":
		printHelp()
		return
	}

	cmd, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printHelp()
		os.Exit(2)
	}

	if err := cmd.run(args[0], args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", args[0], err)
		os.Exit(1)
	}
}

func printHelp() {
	exec := filepath.Base(os.Args[0])

	// Stable order for human consumption: alphabetical by canonical name.
	names := make([]string, 0, len(commands))
	for n, c := range commands {
		if c.help == "" {
			continue // hide aliases
		}
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "  %-36s %s\n", n+":", commands[n].help)
	}

	fmt.Printf(`Certdx tools

Usage:
  %s <command> [options]
  %s --version
  %s --help

Commands:
%s
For command details, use %s <command> --help

Aliases: tx-update, k8s-update, and the legacy "certificates-updater" plurals
all route to the corresponding canonical updater.
`, exec, exec, exec, b.String(), exec)
}
