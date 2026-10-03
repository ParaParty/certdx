package tasks

import (
	"testing"
)

func TestValidForOptions(t *testing.T) {
	cases := []struct {
		args    []string
		wantLen int
		wantErr bool
	}{
		{nil, 0, false},
		{[]string{"--valid-for", "24h"}, 1, false},
		{[]string{"--valid-for", "0"}, 0, true},
		{[]string{"--valid-for", "-1h"}, 0, true},
	}
	for _, c := range cases {
		fs := newFlagSet("test")
		validFor := registerValidForFlag(fs)
		if err := fs.Parse(c.args); err != nil {
			t.Fatalf("parse %v: %v", c.args, err)
		}
		opts, err := validForOptions(fs, *validFor)
		if (err != nil) != c.wantErr {
			t.Errorf("%v: err = %v, wantErr %t", c.args, err, c.wantErr)
		}
		if len(opts) != c.wantLen {
			t.Errorf("%v: got %d options, want %d", c.args, len(opts), c.wantLen)
		}
	}
}
