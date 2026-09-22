package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

const latestReleaseURL = "https://api.github.com/repos/ParaParty/certdx/releases/latest"

type PackageKind string

const (
	PackageDEB PackageKind = "deb"
	PackageRPM PackageKind = "rpm"
)

type PackageInfo struct {
	Kind         PackageKind
	Version      string
	Architecture string
	Executable   string
}

type ReleaseAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
}

type UpdatePlan struct {
	Installed       PackageInfo
	LatestVersion   string
	Asset           ReleaseAsset
	UpdateAvailable bool
	Install         bool
	Force           bool
}

type ServiceRestoreError struct {
	Err error
}

func (e *ServiceRestoreError) Error() string {
	return fmt.Sprintf("package installed, but restoring services failed: %v", e.Err)
}

func (e *ServiceRestoreError) Unwrap() error {
	return e.Err
}

type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)
type interactiveCommandRunner func(ctx context.Context, name string, args ...string) error

type Updater struct {
	HTTPClient     *http.Client
	ReleaseURL     string
	executable     func() (string, error)
	lookPath       func(string) (string, error)
	run            commandRunner
	runInteractive interactiveCommandRunner
	geteuid        func() int
	stat           func(string) (os.FileInfo, error)
	tempDir        string
}

func NewUpdater() *Updater {
	return &Updater{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		ReleaseURL: latestReleaseURL,
		executable: os.Executable,
		lookPath:   exec.LookPath,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
		runInteractive: func(ctx context.Context, name string, args ...string) error {
			command := exec.CommandContext(ctx, name, args...)
			command.Stdin = os.Stdin
			command.Stdout = os.Stdout
			command.Stderr = os.Stderr
			return command.Run()
		},
		geteuid: currentEUID,
		stat:    os.Stat,
	}
}

func (u *Updater) Check(ctx context.Context, force bool) (*UpdatePlan, error) {
	installed, err := u.detectPackage(ctx)
	if err != nil {
		return nil, err
	}

	release, err := u.latestRelease(ctx)
	if err != nil {
		return nil, err
	}
	asset, err := selectPackageAsset(release.Assets, installed.Kind, installed.Architecture)
	if err != nil {
		return nil, err
	}

	installedVersion, err := parseVersion(installed.Version)
	if err != nil {
		return nil, fmt.Errorf("parse installed package version %q: %w", installed.Version, err)
	}
	latestVersion, err := parseVersion(release.TagName)
	if err != nil {
		return nil, fmt.Errorf("parse latest release version %q: %w", release.TagName, err)
	}
	updateAvailable := latestVersion.GreaterThan(installedVersion)

	return &UpdatePlan{
		Installed:       installed,
		LatestVersion:   release.TagName,
		Asset:           asset,
		UpdateAvailable: updateAvailable,
		Install:         updateAvailable || force,
		Force:           force,
	}, nil
}

func (u *Updater) Install(ctx context.Context, plan *UpdatePlan) error {
	if plan == nil || !plan.Install {
		return errors.New("update plan does not require installation")
	}

	packagePath, err := u.downloadPackage(ctx, plan.Asset, plan.Installed.Kind)
	if err != nil {
		return err
	}
	defer os.Remove(packagePath)

	if err := u.inspectPackage(ctx, packagePath, plan); err != nil {
		return err
	}

	privileged, err := u.privilegedRunner(ctx)
	if err != nil {
		return err
	}
	serviceStates := u.snapshotServices(ctx)
	installErr := u.installPackage(ctx, privileged, packagePath, plan)
	restoreErr := u.restoreServices(ctx, privileged, serviceStates)
	if installErr != nil {
		var failures []error
		failures = append(failures, fmt.Errorf("install package: %w", installErr))
		if restoreErr != nil {
			failures = append(failures, fmt.Errorf("restore services: %w", restoreErr))
		}
		return errors.Join(failures...)
	}
	if restoreErr != nil {
		return &ServiceRestoreError{Err: restoreErr}
	}
	return nil
}

func (u *Updater) downloadPackage(ctx context.Context, asset ReleaseAsset, kind PackageKind) (string, error) {
	expectedDigest, err := parseSHA256Digest(asset.Digest)
	if err != nil {
		return "", fmt.Errorf("verify release asset %s: %w", asset.Name, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return "", fmt.Errorf("create package download request: %w", err)
	}
	request.Header.Set("User-Agent", "certdx_tools")
	response, err := u.HTTPClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("download package %s: %w", asset.Name, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
		return "", fmt.Errorf("download package %s: %s: %s", asset.Name, response.Status, strings.TrimSpace(string(message)))
	}

	file, err := os.CreateTemp(u.tempDir, "certdx-update-*."+string(kind))
	if err != nil {
		return "", fmt.Errorf("create temporary package file: %w", err)
	}
	path := file.Name()
	ok := false
	defer func() {
		if !ok {
			file.Close()
			os.Remove(path)
		}
	}()

	digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(file, digest), response.Body); err != nil {
		return "", fmt.Errorf("download package %s: %w", asset.Name, err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync downloaded package: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close downloaded package: %w", err)
	}
	if !digestMatches(digest, expectedDigest) {
		return "", fmt.Errorf("downloaded package %s failed SHA-256 verification", asset.Name)
	}
	ok = true
	return path, nil
}

func parseSHA256Digest(value string) ([]byte, error) {
	algorithm, encoded, ok := strings.Cut(value, ":")
	if !ok || !strings.EqualFold(algorithm, "sha256") {
		return nil, errors.New("missing SHA-256 digest")
	}
	digest, err := hex.DecodeString(encoded)
	if err != nil || len(digest) != sha256.Size {
		return nil, errors.New("malformed SHA-256 digest")
	}
	return digest, nil
}

func digestMatches(actual hash.Hash, expected []byte) bool {
	return string(actual.Sum(nil)) == string(expected)
}

func (u *Updater) inspectPackage(ctx context.Context, packagePath string, plan *UpdatePlan) error {
	var fields []string
	switch plan.Installed.Kind {
	case PackageDEB:
		dpkgDeb, err := u.lookPath("dpkg-deb")
		if err != nil {
			return errors.New("dpkg-deb is required to inspect the downloaded package")
		}
		output, err := u.run(ctx, dpkgDeb, "--field", packagePath)
		if err != nil {
			return commandError("inspect downloaded deb package", output, err)
		}
		metadata := parseDEBFields(string(output))
		fields = []string{metadata["Package"], metadata["Version"], metadata["Architecture"]}
	case PackageRPM:
		rpm, err := u.lookPath("rpm")
		if err != nil {
			return errors.New("rpm is required to inspect the downloaded package")
		}
		output, err := u.run(ctx, rpm, "-qp", "--qf", "%{NAME}\t%{VERSION}\t%{ARCH}\n", packagePath)
		if err != nil {
			return commandError("inspect downloaded RPM package", output, err)
		}
		fields = strings.Fields(string(output))
	default:
		return fmt.Errorf("unsupported package kind %q", plan.Installed.Kind)
	}
	if len(fields) != 3 || fields[0] != "certdx" {
		return errors.New("downloaded package is not the certdx package")
	}
	if fields[2] != plan.Installed.Architecture {
		return fmt.Errorf("downloaded package architecture is %s, expected %s", fields[2], plan.Installed.Architecture)
	}
	packageVersion, err := parseVersion(fields[1])
	if err != nil {
		return fmt.Errorf("parse downloaded package version %q: %w", fields[1], err)
	}
	latestVersion, err := parseVersion(plan.LatestVersion)
	if err != nil {
		return fmt.Errorf("parse latest release version %q: %w", plan.LatestVersion, err)
	}
	if !packageVersion.Equal(latestVersion) {
		return fmt.Errorf("downloaded package version is %s, expected %s", fields[1], plan.LatestVersion)
	}
	return nil
}

func parseDEBFields(output string) map[string]string {
	fields := make(map[string]string)
	for line := range strings.SplitSeq(output, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok {
			fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	return fields
}

type privilegedRunner func(ctx context.Context, name string, args ...string) error

func (u *Updater) privilegedRunner(ctx context.Context) (privilegedRunner, error) {
	if u.geteuid() == 0 {
		return privilegedRunner(u.runInteractive), nil
	}
	sudo, err := u.lookPath("sudo")
	if err != nil {
		return nil, errors.New("root privileges are required; install sudo or run certdx_tools update as root")
	}
	if err := u.runInteractive(ctx, sudo, "-v"); err != nil {
		return nil, fmt.Errorf("authenticate with sudo: %w", err)
	}
	return func(ctx context.Context, name string, args ...string) error {
		return u.runInteractive(ctx, sudo, append([]string{name}, args...)...)
	}, nil
}

func (u *Updater) installPackage(ctx context.Context, privileged privilegedRunner, packagePath string, plan *UpdatePlan) error {
	switch plan.Installed.Kind {
	case PackageDEB:
		dpkg, err := u.lookPath("dpkg")
		if err != nil {
			return errors.New("dpkg is required to install the update")
		}
		return privileged(ctx, dpkg, "--install", packagePath)
	case PackageRPM:
		rpm, err := u.lookPath("rpm")
		if err != nil {
			return errors.New("rpm is required to install the update")
		}
		args := []string{"--upgrade"}
		if plan.Force {
			args = append(args, "--replacepkgs", "--oldpackage")
		}
		return privileged(ctx, rpm, append(args, packagePath)...)
	default:
		return fmt.Errorf("unsupported package kind %q", plan.Installed.Kind)
	}
}

type serviceState struct {
	Name    string
	Enabled bool
	Active  bool
}

var updateServices = []string{"certdx-server.service", "certdx-client.service"}

func (u *Updater) snapshotServices(ctx context.Context) []serviceState {
	if _, err := u.stat("/run/systemd/system"); err != nil {
		return nil
	}
	systemctl, err := u.lookPath("systemctl")
	if err != nil {
		return nil
	}
	states := make([]serviceState, 0, len(updateServices))
	for _, name := range updateServices {
		enabled, _ := u.run(ctx, systemctl, "is-enabled", name)
		active, _ := u.run(ctx, systemctl, "is-active", name)
		states = append(states, serviceState{
			Name:    name,
			Enabled: strings.TrimSpace(string(enabled)) == "enabled",
			Active:  strings.TrimSpace(string(active)) == "active",
		})
	}
	return states
}

func (u *Updater) restoreServices(ctx context.Context, privileged privilegedRunner, states []serviceState) error {
	if len(states) == 0 {
		return nil
	}
	systemctl, err := u.lookPath("systemctl")
	if err != nil {
		return errors.New("systemctl disappeared while restoring certdx services")
	}
	var failures []error
	for _, state := range states {
		enableAction := "disable"
		if state.Enabled {
			enableAction = "enable"
		}
		if err := privileged(ctx, systemctl, enableAction, state.Name); err != nil {
			failures = append(failures, fmt.Errorf("%s %s: %w", enableAction, state.Name, err))
		}
		activeAction := "stop"
		if state.Active {
			activeAction = "start"
		}
		if err := privileged(ctx, systemctl, activeAction, state.Name); err != nil {
			failures = append(failures, fmt.Errorf("%s %s: %w", activeAction, state.Name, err))
		}
	}
	return errors.Join(failures...)
}

func commandError(action string, output []byte, err error) error {
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w: %s", action, err, message)
}

func (u *Updater) detectPackage(ctx context.Context) (PackageInfo, error) {
	executable, err := u.executable()
	if err != nil {
		return PackageInfo{}, fmt.Errorf("locate running executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}

	var detected []PackageInfo
	if dpkgQuery, err := u.lookPath("dpkg-query"); err == nil {
		if info, ok, err := u.detectDEB(ctx, dpkgQuery, executable); err != nil {
			return PackageInfo{}, err
		} else if ok {
			detected = append(detected, info)
		}
	}
	if rpm, err := u.lookPath("rpm"); err == nil {
		if info, ok, err := u.detectRPM(ctx, rpm, executable); err != nil {
			return PackageInfo{}, err
		} else if ok {
			detected = append(detected, info)
		}
	}

	switch len(detected) {
	case 1:
		return detected[0], nil
	case 0:
		return PackageInfo{}, errors.New("the running certdx_tools executable is not owned by the installed certdx deb or RPM package")
	default:
		return PackageInfo{}, errors.New("the running certdx_tools executable is reported by both deb and RPM package databases")
	}
}

func (u *Updater) detectDEB(ctx context.Context, dpkgQuery, executable string) (PackageInfo, bool, error) {
	ownerOutput, err := u.run(ctx, dpkgQuery, "--search", executable)
	if err != nil {
		return PackageInfo{}, false, nil
	}
	owner := strings.TrimSpace(strings.SplitN(string(ownerOutput), ": ", 2)[0])
	owner, _, _ = strings.Cut(owner, ":")
	if owner != "certdx" {
		return PackageInfo{}, false, nil
	}

	output, err := u.run(ctx, dpkgQuery, "--show", "--showformat=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n", "certdx")
	if err != nil {
		return PackageInfo{}, false, commandError("query installed certdx deb package", output, err)
	}
	fields := strings.Fields(string(output))
	if len(fields) != 4 || strings.TrimSuffix(fields[0], ":"+fields[2]) != "certdx" || fields[3] != "installed" {
		return PackageInfo{}, false, fmt.Errorf("installed certdx deb package returned unexpected metadata %q", strings.TrimSpace(string(output)))
	}
	if !supportedArchitecture(PackageDEB, fields[2]) {
		return PackageInfo{}, false, fmt.Errorf("installed certdx deb architecture %q is not supported by published packages", fields[2])
	}
	return PackageInfo{Kind: PackageDEB, Version: fields[1], Architecture: fields[2], Executable: executable}, true, nil
}

func (u *Updater) detectRPM(ctx context.Context, rpm, executable string) (PackageInfo, bool, error) {
	output, err := u.run(ctx, rpm, "-qf", "--qf", "%{NAME}\t%{VERSION}\t%{ARCH}\n", executable)
	if err != nil {
		return PackageInfo{}, false, nil
	}
	fields := strings.Fields(string(output))
	if len(fields) != 3 || fields[0] != "certdx" {
		return PackageInfo{}, false, nil
	}
	if !supportedArchitecture(PackageRPM, fields[2]) {
		return PackageInfo{}, false, fmt.Errorf("installed certdx RPM architecture %q is not supported by published packages", fields[2])
	}
	return PackageInfo{Kind: PackageRPM, Version: fields[1], Architecture: fields[2], Executable: executable}, true, nil
}

type githubRelease struct {
	TagName    string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
	Assets     []ReleaseAsset `json:"assets"`
}

func (u *Updater) latestRelease(ctx context.Context) (githubRelease, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.ReleaseURL, nil)
	if err != nil {
		return githubRelease{}, fmt.Errorf("create GitHub release request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "certdx_tools")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	response, err := u.HTTPClient.Do(request)
	if err != nil {
		return githubRelease{}, fmt.Errorf("fetch latest GitHub release: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
		return githubRelease{}, fmt.Errorf("fetch latest GitHub release: %s: %s", response.Status, strings.TrimSpace(string(message)))
	}

	var release githubRelease
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
	if err := decoder.Decode(&release); err != nil {
		return githubRelease{}, fmt.Errorf("decode latest GitHub release: %w", err)
	}
	if release.TagName == "" || release.Draft || release.Prerelease {
		return githubRelease{}, errors.New("GitHub latest release is missing a stable tag")
	}
	return release, nil
}

func selectPackageAsset(assets []ReleaseAsset, kind PackageKind, architecture string) (ReleaseAsset, error) {
	var suffix string
	switch kind {
	case PackageDEB:
		suffix = "_" + architecture + ".deb"
	case PackageRPM:
		suffix = "." + architecture + ".rpm"
	default:
		return ReleaseAsset{}, fmt.Errorf("unsupported package kind %q", kind)
	}

	var matches []ReleaseAsset
	for _, asset := range assets {
		if strings.HasPrefix(asset.Name, "certdx") && strings.HasSuffix(asset.Name, suffix) {
			matches = append(matches, asset)
		}
	}
	if len(matches) != 1 {
		return ReleaseAsset{}, fmt.Errorf("latest release has %d certdx %s package assets for architecture %s", len(matches), kind, architecture)
	}
	if matches[0].URL == "" || matches[0].Digest == "" {
		return ReleaseAsset{}, fmt.Errorf("release asset %s is missing its download URL or digest", matches[0].Name)
	}
	return matches[0], nil
}

func supportedArchitecture(kind PackageKind, architecture string) bool {
	switch kind {
	case PackageDEB:
		return architecture == "amd64" || architecture == "arm64" || architecture == "armhf"
	case PackageRPM:
		return architecture == "x86_64" || architecture == "aarch64" || architecture == "armv7hl"
	default:
		return false
	}
}

func parseVersion(value string) (*semver.Version, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if epoch, rest, ok := strings.Cut(value, ":"); ok && epoch != "" {
		value = rest
	}
	value = strings.ReplaceAll(value, "~", "-")
	return semver.NewVersion(value)
}
