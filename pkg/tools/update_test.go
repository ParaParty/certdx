package tools

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckDEBUpdate(t *testing.T) {
	updater := testUpdater(t, `{
		"tag_name":"v0.8.0",
		"assets":[
			{"name":"certdx_0.8.0_amd64.deb","browser_download_url":"https://example.test/certdx.deb","digest":"sha256:abc"},
			{"name":"certdx-0.8.0-1.x86_64.rpm","browser_download_url":"https://example.test/certdx.rpm","digest":"sha256:def"}
		]
	}`)
	updater.lookPath = lookupOnly("dpkg-query")
	updater.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch args[0] {
		case "--search":
			return []byte("certdx: /usr/bin/certdx_tools\n"), nil
		case "--show":
			return []byte("certdx\t0.7.0\tamd64\tinstalled\n"), nil
		default:
			return nil, fmt.Errorf("unexpected args: %v", args)
		}
	}

	plan, err := updater.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if plan.Installed.Kind != PackageDEB || plan.Installed.Version != "0.7.0" {
		t.Fatalf("installed = %+v", plan.Installed)
	}
	if !plan.UpdateAvailable || !plan.Install {
		t.Fatalf("expected installable update: %+v", plan)
	}
	if plan.Asset.Name != "certdx_0.8.0_amd64.deb" {
		t.Fatalf("asset = %q", plan.Asset.Name)
	}
}

func TestCheckRPMNoUpdateUnlessForced(t *testing.T) {
	updater := testUpdater(t, `{
		"tag_name":"v0.7.0",
		"assets":[{"name":"certdx-0.7.0-1.x86_64.rpm","browser_download_url":"https://example.test/certdx.rpm","digest":"sha256:abc"}]
	}`)
	updater.lookPath = lookupOnly("rpm")
	updater.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("certdx\t0.7.0\tx86_64\n"), nil
	}

	plan, err := updater.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if plan.UpdateAvailable || plan.Install {
		t.Fatalf("unexpected update: %+v", plan)
	}

	forced, err := updater.Check(context.Background(), true)
	if err != nil {
		t.Fatalf("forced Check: %v", err)
	}
	if forced.UpdateAvailable || !forced.Install {
		t.Fatalf("forced plan = %+v", forced)
	}
}

func TestCheckRejectsUnownedExecutable(t *testing.T) {
	updater := testUpdater(t, `{}`)
	updater.lookPath = lookupOnly("dpkg-query")
	updater.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, fmt.Errorf("not owned")
	}

	_, err := updater.Check(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheckRejectsUnsupportedPackageArchitecture(t *testing.T) {
	updater := testUpdater(t, `{}`)
	updater.lookPath = lookupOnly("dpkg-query")
	updater.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "--search" {
			return []byte("certdx:i386: /usr/bin/certdx_tools\n"), nil
		}
		return []byte("certdx:i386\t0.7.0\ti386\tinstalled\n"), nil
	}

	_, err := updater.Check(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "i386") {
		t.Fatalf("error = %v", err)
	}
}

func TestSelectPackageAssetRequiresExactSingleMatch(t *testing.T) {
	assets := []ReleaseAsset{
		{Name: "certdx_0.8.0_amd64.deb", URL: "one", Digest: "sha256:one"},
		{Name: "certdx_0.8.0_arm64.deb", URL: "two", Digest: "sha256:two"},
		{Name: "certdx_linux_amd64.tar.gz", URL: "three", Digest: "sha256:three"},
	}

	asset, err := selectPackageAsset(assets, PackageDEB, "amd64")
	if err != nil {
		t.Fatalf("selectPackageAsset: %v", err)
	}
	if asset.Name != "certdx_0.8.0_amd64.deb" {
		t.Fatalf("asset = %q", asset.Name)
	}

	assets = append(assets, ReleaseAsset{Name: "certdx_duplicate_amd64.deb", URL: "four", Digest: "sha256:four"})
	if _, err := selectPackageAsset(assets, PackageDEB, "amd64"); err == nil {
		t.Fatal("expected ambiguous asset error")
	}
}

func TestParseVersionNFPMPrerelease(t *testing.T) {
	prerelease, err := parseVersion("1:0.8.0~5.gabc")
	if err != nil {
		t.Fatalf("parse prerelease: %v", err)
	}
	release, err := parseVersion("v0.8.0")
	if err != nil {
		t.Fatalf("parse release: %v", err)
	}
	if !release.GreaterThan(prerelease) {
		t.Fatalf("release %s should be newer than %s", release, prerelease)
	}
}

func TestInstallDEBVerifiesAndRestoresServices(t *testing.T) {
	packageBody := []byte("deb package")
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(packageBody))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(packageBody)
	}))
	defer server.Close()

	updater := NewUpdater()
	updater.tempDir = t.TempDir()
	updater.geteuid = func() int { return 0 }
	updater.stat = func(string) (os.FileInfo, error) { return nil, nil }
	updater.lookPath = lookupOnly("dpkg-deb", "dpkg", "systemctl")
	updater.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch filepath.Base(name) {
		case "dpkg-deb":
			return []byte("Package: certdx\nVersion: 0.8.0\nArchitecture: amd64\n"), nil
		case "systemctl":
			if args[0] == "is-enabled" && args[1] == "certdx-server.service" {
				return []byte("enabled\n"), nil
			}
			if args[0] == "is-active" && args[1] == "certdx-server.service" {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), fmt.Errorf("inactive")
		default:
			return nil, fmt.Errorf("unexpected command %s %v", name, args)
		}
	}
	var commands []string
	updater.runInteractive = func(_ context.Context, name string, args ...string) error {
		commands = append(commands, filepath.Base(name)+" "+strings.Join(args, " "))
		return nil
	}

	plan := &UpdatePlan{
		Installed:     PackageInfo{Kind: PackageDEB, Version: "0.7.0", Architecture: "amd64"},
		LatestVersion: "v0.8.0",
		Asset:         ReleaseAsset{Name: "certdx_0.8.0_amd64.deb", URL: server.URL, Digest: digest},
		Install:       true,
	}
	if err := updater.Install(context.Background(), plan); err != nil {
		t.Fatalf("Install: %v", err)
	}

	joined := strings.Join(commands, "\n")
	for _, expected := range []string{
		"dpkg --install ",
		"systemctl enable certdx-server.service",
		"systemctl start certdx-server.service",
		"systemctl disable certdx-client.service",
		"systemctl stop certdx-client.service",
	} {
		if !strings.Contains(joined, expected) {
			t.Errorf("commands missing %q:\n%s", expected, joined)
		}
	}
	entries, err := os.ReadDir(updater.tempDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary package was not removed: %v", entries)
	}
}

func TestInstallRejectsDigestMismatchBeforeCommands(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "tampered")
	}))
	defer server.Close()

	updater := NewUpdater()
	updater.tempDir = t.TempDir()
	called := false
	updater.runInteractive = func(context.Context, string, ...string) error {
		called = true
		return nil
	}
	plan := &UpdatePlan{
		Installed:     PackageInfo{Kind: PackageDEB, Architecture: "amd64"},
		LatestVersion: "v0.8.0",
		Asset:         ReleaseAsset{Name: "certdx.deb", URL: server.URL, Digest: "sha256:" + strings.Repeat("0", 64)},
		Install:       true,
	}
	if err := updater.Install(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("command ran before digest verification")
	}
}

func TestInstallUsesSudoAndRestoresAfterInstallerFailure(t *testing.T) {
	packageBody := []byte("rpm package")
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(packageBody))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(packageBody)
	}))
	defer server.Close()

	updater := NewUpdater()
	updater.tempDir = t.TempDir()
	updater.geteuid = func() int { return 1000 }
	updater.stat = func(string) (os.FileInfo, error) { return nil, nil }
	updater.lookPath = lookupOnly("rpm", "sudo", "systemctl")
	updater.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if filepath.Base(name) == "rpm" {
			return []byte("certdx\t0.8.0\tx86_64\n"), nil
		}
		if args[0] == "is-enabled" {
			return []byte("enabled\n"), nil
		}
		return []byte("active\n"), nil
	}
	var commands []string
	updater.runInteractive = func(_ context.Context, name string, args ...string) error {
		command := filepath.Base(name) + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if strings.Contains(command, "rpm --upgrade") {
			return fmt.Errorf("installer failed")
		}
		return nil
	}
	plan := &UpdatePlan{
		Installed:     PackageInfo{Kind: PackageRPM, Architecture: "x86_64"},
		LatestVersion: "v0.8.0",
		Asset:         ReleaseAsset{Name: "certdx.rpm", URL: server.URL, Digest: digest},
		Install:       true,
		Force:         true,
	}
	err := updater.Install(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "installer failed") {
		t.Fatalf("error = %v", err)
	}
	joined := strings.Join(commands, "\n")
	for _, expected := range []string{
		"sudo -v",
		"sudo /usr/bin/rpm --upgrade --replacepkgs --oldpackage",
		"sudo /usr/bin/systemctl enable certdx-server.service",
		"sudo /usr/bin/systemctl start certdx-client.service",
	} {
		if !strings.Contains(joined, expected) {
			t.Errorf("commands missing %q:\n%s", expected, joined)
		}
	}
}

func TestInstallReportsPackageInstalledWhenRestoreFails(t *testing.T) {
	packageBody := []byte("deb package")
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(packageBody))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(packageBody)
	}))
	defer server.Close()

	updater := NewUpdater()
	updater.tempDir = t.TempDir()
	updater.geteuid = func() int { return 0 }
	updater.stat = func(string) (os.FileInfo, error) { return nil, nil }
	updater.lookPath = lookupOnly("dpkg-deb", "dpkg", "systemctl")
	updater.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if filepath.Base(name) == "dpkg-deb" {
			return []byte("Package: certdx\nVersion: 0.8.0\nArchitecture: amd64\n"), nil
		}
		if args[0] == "is-enabled" {
			return []byte("enabled\n"), nil
		}
		return []byte("active\n"), nil
	}
	updater.runInteractive = func(_ context.Context, name string, _ ...string) error {
		if filepath.Base(name) == "systemctl" {
			return fmt.Errorf("systemctl failed")
		}
		return nil
	}
	plan := &UpdatePlan{
		Installed:     PackageInfo{Kind: PackageDEB, Architecture: "amd64"},
		LatestVersion: "v0.8.0",
		Asset:         ReleaseAsset{Name: "certdx.deb", URL: server.URL, Digest: digest},
		Install:       true,
	}
	err := updater.Install(context.Background(), plan)
	var restoreError *ServiceRestoreError
	if !errors.As(err, &restoreError) {
		t.Fatalf("error = %v, want ServiceRestoreError", err)
	}
}

func testUpdater(t *testing.T, response string) *Updater {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("User-Agent") != "certdx_tools" {
			t.Errorf("User-Agent = %q", request.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, response)
	}))
	t.Cleanup(server.Close)

	updater := NewUpdater()
	updater.ReleaseURL = server.URL
	updater.executable = func() (string, error) { return "/usr/bin/certdx_tools", nil }
	return updater
}

func lookupOnly(names ...string) func(string) (string, error) {
	available := make(map[string]bool, len(names))
	for _, name := range names {
		available[name] = true
	}
	return func(name string) (string, error) {
		if available[name] {
			return "/usr/bin/" + name, nil
		}
		return "", fmt.Errorf("not found")
	}
}
