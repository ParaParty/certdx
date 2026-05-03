// Package cli holds small process-level helpers shared by the certdx
// command-line entrypoints (server, client, tools). It deliberately
// stays stdlib-only and free of business logic so each main package
// can stay tiny and declarative.
package cli

import (
	"fmt"
	"io"
	"os"
)

// Version is the build-time identity of a certdx binary. The fields are
// usually populated via `-ldflags` on the build target.
type Version struct {
	Name   string
	Commit string
	Date   string
}

// String formats the version like
// "Certdx server abc123, built at 2026-05-01".
func (v Version) String() string {
	return fmt.Sprintf("Certdx %s %s, built at %s", v.Name, v.Commit, v.Date)
}

// Print writes the version to stdout followed by a newline.
func (v Version) Print() {
	fmt.Fprintln(os.Stdout, v.String())
}

// Fprint writes the version to w followed by a newline.
func (v Version) Fprint(w io.Writer) {
	fmt.Fprintln(w, v.String())
}
