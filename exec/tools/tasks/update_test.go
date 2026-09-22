package tasks

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"pkg.para.party/certdx/pkg/tools"
)

type fakeUpdater struct {
	plan         *tools.UpdatePlan
	checkForce   bool
	installCalls int
	installError error
}

func (updater *fakeUpdater) Check(_ context.Context, force bool) (*tools.UpdatePlan, error) {
	updater.checkForce = force
	return updater.plan, nil
}

func (updater *fakeUpdater) Install(_ context.Context, _ *tools.UpdatePlan) error {
	updater.installCalls++
	return updater.installError
}

func TestUpdateCommandConfirmsBeforeInstall(t *testing.T) {
	updater := &fakeUpdater{plan: updateTestPlan()}
	var output bytes.Buffer
	command := updateCommand{
		updater:    updater,
		input:      strings.NewReader("yes\n"),
		output:     &output,
		isTerminal: func() bool { return true },
	}

	if err := command.run(context.Background(), "update", nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	if updater.installCalls != 1 {
		t.Fatalf("install calls = %d, want 1", updater.installCalls)
	}
	if !strings.Contains(output.String(), "Continue? [y/N]") {
		t.Fatalf("output missing confirmation: %q", output.String())
	}
}

func TestUpdateCommandDeclineAndEOFCancel(t *testing.T) {
	for _, input := range []string{"n\n", "\n", ""} {
		t.Run(strings.ReplaceAll(input, "\n", "newline"), func(t *testing.T) {
			updater := &fakeUpdater{plan: updateTestPlan()}
			var output bytes.Buffer
			command := updateCommand{
				updater:    updater,
				input:      strings.NewReader(input),
				output:     &output,
				isTerminal: func() bool { return true },
			}
			if err := command.run(context.Background(), "update", nil); err != nil {
				t.Fatalf("run: %v", err)
			}
			if updater.installCalls != 0 {
				t.Fatalf("install calls = %d, want 0", updater.installCalls)
			}
			if !strings.Contains(output.String(), "Update canceled.") {
				t.Fatalf("output = %q", output.String())
			}
		})
	}
}

func TestUpdateCommandNonInteractiveRequiresYes(t *testing.T) {
	updater := &fakeUpdater{plan: updateTestPlan()}
	command := updateCommand{
		updater:    updater,
		input:      strings.NewReader("yes\n"),
		output:     ioDiscard{},
		isTerminal: func() bool { return false },
	}

	err := command.run(context.Background(), "update", nil)
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error = %v", err)
	}
	if updater.installCalls != 0 {
		t.Fatalf("install calls = %d, want 0", updater.installCalls)
	}
}

func TestUpdateCommandYesForceAndCheck(t *testing.T) {
	t.Run("yes force", func(t *testing.T) {
		updater := &fakeUpdater{plan: updateTestPlan()}
		command := updateCommand{updater: updater, input: strings.NewReader(""), output: ioDiscard{}, isTerminal: func() bool { return false }}
		if err := command.run(context.Background(), "update", []string{"--force", "--yes"}); err != nil {
			t.Fatalf("run: %v", err)
		}
		if !updater.checkForce || updater.installCalls != 1 {
			t.Fatalf("force = %t, install calls = %d", updater.checkForce, updater.installCalls)
		}
	})

	t.Run("check", func(t *testing.T) {
		updater := &fakeUpdater{plan: updateTestPlan()}
		command := updateCommand{updater: updater, input: strings.NewReader(""), output: ioDiscard{}, isTerminal: func() bool { return false }}
		if err := command.run(context.Background(), "update", []string{"--check"}); err != nil {
			t.Fatalf("run: %v", err)
		}
		if updater.installCalls != 0 {
			t.Fatalf("install calls = %d, want 0", updater.installCalls)
		}
	})
}

func TestUpdateCommandReportsUpdateBeforeRestoreError(t *testing.T) {
	updater := &fakeUpdater{
		plan:         updateTestPlan(),
		installError: &tools.ServiceRestoreError{Err: fmt.Errorf("systemctl failed")},
	}
	var output bytes.Buffer
	command := updateCommand{updater: updater, input: strings.NewReader(""), output: &output, isTerminal: func() bool { return false }}
	err := command.run(context.Background(), "update", []string{"--yes"})
	if err == nil || !strings.Contains(err.Error(), "restoring services failed") {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(output.String(), "Updated certdx from 0.7.0 to v0.8.0.") {
		t.Fatalf("output = %q", output.String())
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(value []byte) (int, error) { return len(value), nil }

func updateTestPlan() *tools.UpdatePlan {
	return &tools.UpdatePlan{
		Installed:       tools.PackageInfo{Kind: tools.PackageDEB, Version: "0.7.0", Architecture: "amd64"},
		LatestVersion:   "v0.8.0",
		Asset:           tools.ReleaseAsset{Name: "certdx_0.8.0_amd64.deb"},
		UpdateAvailable: true,
		Install:         true,
	}
}
