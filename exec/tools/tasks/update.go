package tasks

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
	"pkg.para.party/certdx/pkg/tools"
)

type updaterService interface {
	Check(ctx context.Context, force bool) (*tools.UpdatePlan, error)
	Install(ctx context.Context, plan *tools.UpdatePlan) error
}

type updateCommand struct {
	updater    updaterService
	input      io.Reader
	output     io.Writer
	isTerminal func() bool
}

func Update(name string, args []string) error {
	command := updateCommand{
		updater: tools.NewUpdater(),
		input:   os.Stdin,
		output:  os.Stdout,
		isTerminal: func() bool {
			return term.IsTerminal(int(os.Stdin.Fd()))
		},
	}
	return command.run(context.Background(), name, args)
}

func (command updateCommand) run(ctx context.Context, name string, args []string) error {
	fs := newFlagSet(name)
	fs.SetOutput(command.output)
	check := fs.Bool("check", false, "Check for an update without installing it")
	force := fs.Bool("force", false, "Reinstall or downgrade to the latest stable release")
	yes := fs.BoolP("yes", "y", false, "Approve the update without prompting")
	help := fs.BoolP("help", "h", false, "Print help")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		fs.PrintDefaults()
		return nil
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	plan, err := command.updater.Check(ctx, *force)
	if err != nil {
		return err
	}
	fmt.Fprintf(command.output, "Installed: certdx %s (%s/%s)\n", plan.Installed.Version, plan.Installed.Kind, plan.Installed.Architecture)
	fmt.Fprintf(command.output, "Latest:    %s\n", plan.LatestVersion)
	fmt.Fprintf(command.output, "Package:   %s\n", plan.Asset.Name)

	if !plan.Install {
		fmt.Fprintln(command.output, "No newer stable release is available.")
		return nil
	}
	if *check {
		if plan.UpdateAvailable {
			fmt.Fprintln(command.output, "An update is available.")
		} else {
			fmt.Fprintln(command.output, "The latest release is available for forced installation.")
		}
		return nil
	}

	if !*yes {
		if !command.isTerminal() {
			return errors.New("confirmation requires an interactive terminal; rerun with --yes")
		}
		confirmed, err := command.confirm()
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(command.output, "Update canceled.")
			return nil
		}
	}

	if err := command.updater.Install(ctx, plan); err != nil {
		var restoreError *tools.ServiceRestoreError
		if errors.As(err, &restoreError) {
			fmt.Fprintf(command.output, "Updated certdx from %s to %s.\n", plan.Installed.Version, plan.LatestVersion)
		}
		return err
	}
	fmt.Fprintf(command.output, "Updated certdx from %s to %s.\n", plan.Installed.Version, plan.LatestVersion)
	return nil
}

func (command updateCommand) confirm() (bool, error) {
	fmt.Fprint(command.output, "Continue? [y/N] ")
	answer, err := bufio.NewReader(command.input).ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
