package tasks

import flag "github.com/spf13/pflag"

// newFlagSet constructs an ExitOnError FlagSet labelled with the
// sub-command name. Centralising the constructor keeps the per-task
// boilerplate minimal and means every sub-command picks up the same
// parse-error behaviour.
func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ExitOnError)
}
