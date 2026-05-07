package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"pkg.para.party/certdx/exec/tools/tasks"
	"pkg.para.party/certdx/exec/tools/tasks/kubernetesCertificateUpdater"
	"pkg.para.party/certdx/exec/tools/tasks/txcCertificateUpdater"
	"pkg.para.party/certdx/pkg/cli"
)

// Populated via -ldflags at build time.
var (
	buildTag  string
	buildDate string
)

// taskFunc is the shared signature implemented by every sub-command.
type taskFunc func(name string, args []string) error

// command bundles a task with its short help line and optional aliases.
type command struct {
	run     taskFunc
	help    string
	aliases []string
}

// commandGroup is a named section in the help output.
type commandGroup struct {
	title string
	names []string
}

// commands is the registry of canonical sub-commands.
var commands = map[string]command{
	"show-certs":     {tasks.ShowCerts, "Show cached certificates on the server", nil},
	"google-account": {tasks.RegisterGoogleAccount, "Register a Google ACME EAB account", nil},
	"make-ca":        {tasks.MakeCA, "Generate mTLS CA certificate and key", nil},
	"make-server":    {tasks.MakeServer, "Generate mTLS server certificate and key", nil},
	"make-client":    {tasks.MakeClient, "Generate mTLS client certificate and key", nil},
	"tencent-cloud-certificate-updater": {txcCertificateUpdater.TencentCloudReplaceCertificate,
		"Update expiring Tencent Cloud certificates",
		[]string{"tx-update", "tencent-cloud-certificates-updater"}},
	"kubernetes-certificate-updater": {kubernetesCertificateUpdater.KubernetesReplaceCertificate,
		"Update annotated Kubernetes TLS secrets",
		[]string{"k8s-update", "k8s-certificate-updater"}},
}

// lookup maps every name (canonical + aliases) to the canonical command
// name so dispatch works for both.
var lookup map[string]string

func init() {
	lookup = make(map[string]string, len(commands)*2)
	for name, cmd := range commands {
		lookup[name] = name
		for _, alias := range cmd.aliases {
			lookup[alias] = name
		}
	}
}

// groups controls the order and grouping of commands in the help output.
var groups = []commandGroup{
	{"Certificate Inspection", []string{"show-certs"}},
	{"ACME", []string{"google-account"}},
	{"mTLS Setup", []string{"make-ca", "make-server", "make-client"}},
	{"Certificate Updaters", []string{"tencent-cloud-certificate-updater", "kubernetes-certificate-updater"}},
}

func main() {
	ver := cli.Version{Name: "tools", Tag: buildTag, Date: buildDate}

	args := os.Args[1:]
	if len(args) == 0 {
		printHelp()
		return
	}

	switch args[0] {
	case "-v", "--version":
		ver.Print()
		return
	case "-h", "--help":
		printHelp()
		return
	}

	canonical, ok := lookup[args[0]]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printHelp()
		os.Exit(2)
	}

	cmd := commands[canonical]
	if err := cmd.run(args[0], args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", args[0], err)
		os.Exit(1)
	}
}

func printHelp() {
	exec := filepath.Base(os.Args[0])

	var b strings.Builder
	for i, g := range groups {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "  %s:\n", g.title)
		for _, name := range g.names {
			cmd := commands[name]
			fmt.Fprintf(&b, "    %-38s %s\n", name, cmd.help)
			if len(cmd.aliases) > 0 {
				fmt.Fprintf(&b, "    %-38s aliases: %s\n", "", strings.Join(cmd.aliases, ", "))
			}
		}
	}

	fmt.Printf(`Certdx tools

Usage:
  %s <command> [options]
  %s --version
  %s --help

Commands:
%s
Use %s <command> --help for command details.
`, exec, exec, exec, b.String(), exec)
}
