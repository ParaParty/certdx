package cli

import (
	"bytes"
	"testing"
)

func TestVersionString(t *testing.T) {
	v := Version{Name: "server", Tag: "v0.4.5", Date: "2026-05-01"}
	got := v.String()
	want := "Certdx server v0.4.5, built at 2026-05-01"
	if got != want {
		t.Fatalf("Version.String:\n got:  %s\n want: %s", got, want)
	}
}

func TestVersionFprintWritesNewline(t *testing.T) {
	v := Version{Name: "client", Tag: "v0.4.5-dirty", Date: "2026-05-04"}
	var buf bytes.Buffer
	v.Fprint(&buf)
	got := buf.String()
	want := "Certdx client v0.4.5-dirty, built at 2026-05-04\n"
	if got != want {
		t.Fatalf("Version.Fprint:\n got:  %q\n want: %q", got, want)
	}
}

func TestVersionStringEmptyFields(t *testing.T) {
	// Empty fields should still produce a parseable line — useful when
	// ldflags weren't injected (e.g. local `go run`).
	v := Version{}
	got := v.String()
	want := "Certdx  , built at "
	if got != want {
		t.Fatalf("Version.String empty:\n got:  %q\n want: %q", got, want)
	}
}
