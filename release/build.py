#! /usr/bin/python3
"""Build certdx + caddy_certdx for a single (goos, goarch).

Usage
-----

    python3 build.py [<goos>] [<goarch>] [--dev]

`goos` and `goarch` are optional and default to the host platform
(`go env GOOS` / `go env GOARCH`). They must be set together.

Examples:

    python3 build.py linux amd64           # release: stripped + archived
    python3 build.py --dev                 # dev for host platform
    python3 build.py darwin arm64 --dev    # dev for explicit target

Modes
-----

Release (default): build certdx_<goos>_<goarch> and caddy_certdx_<goos>_<goarch>,
strip symbols, copy config / systemd-service / LICENSE, and archive each
into .tar.gz / .zip.

Dev (--dev): keep symbols (binaries are debuggable), skip the
config / systemd-service / LICENSE copy step (the dev dir stays
binary-only), and leave the binaries inside `certdx_<goos>_<goarch>/`
and `caddy_certdx_<goos>_<goarch>/` instead of archiving.

The release CI workflow drives the full GOOS/GOARCH matrix by calling
this script once per target.
"""

import argparse
import datetime
import os
from pathlib import Path
import shutil
import string
import subprocess
import sys

# Files to include in the certdx release pack (relative to repo root).
# Directories are copied recursively; files are copied individually.
CERTDX_COPY = [
    'config/client_config.toml',
    'config/client_config_full.toml',
    'config/client_k8s.toml',
    'config/client_tencentcloud_certificate_updater.toml',
    'config/server_config.toml',
    'config/server_config_full.toml',
    'systemd-service/certdx-client.service',
    'systemd-service/certdx-server.service',
    'LICENSE',
]

# Files to include in the caddy_certdx release pack.
CADDY_COPY = [
    'config/Caddyfile_full',
    'LICENSE',
]

# certdx executables: (binary suffix, source module path relative to repo root)
EXECS = [
    ('server', 'exec/server'),
    ('client', 'exec/client'),
    ('tools',  'exec/tools'),
]

# GOARCH -> (nfpm arch token, deb filename arch, rpm filename arch).
# nfpm v2 accepts amd64/arm64 directly; arm7 -> debian armhf / rpm armv7hl.
NFPM_ARCH_MAP = {
    'amd64': ('amd64', 'amd64',  'x86_64'),
    'arm64': ('arm64', 'arm64',  'aarch64'),
    'arm':   ('arm7',  'armhf',  'armv7hl'),
}


def host_target() -> tuple[str, str]:
    goos = subprocess.run(
        ['go', 'env', 'GOOS'], check=True, capture_output=True,
    ).stdout.decode().strip()
    goarch = subprocess.run(
        ['go', 'env', 'GOARCH'], check=True, capture_output=True,
    ).stdout.decode().strip()
    return goos, goarch


def find_xcaddy() -> Path:
    xcaddy = shutil.which("xcaddy")
    if xcaddy:
        return Path(xcaddy)
    # Not on PATH — try the conventional go install location.
    fallback = Path.home() / "go" / "bin" / "xcaddy"
    if fallback.is_file():
        return fallback
    sys.exit("Error: xcaddy is not installed. Install it before running build.py "
             "(`go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest`).")


def find_nfpm() -> Path:
    nfpm = shutil.which("nfpm")
    if nfpm:
        return Path(nfpm)
    fallback = Path.home() / "go" / "bin" / "nfpm"
    if fallback.is_file():
        return fallback
    sys.exit("Error: nfpm is not installed. Install it before running build.py "
             "(`go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`).")


def nfpm_version(build_tag: str) -> str:
    """Convert `git describe` output to a deb/rpm-friendly version.

    Mapping:
      v1.2.3                            -> 1.2.3
      v1.2.3-dirty                      -> 1.2.3~dirty
      v1.2.3-5-g<sha>[-dirty]           -> 1.2.3~5.g<sha>[.dirty]
      <sha>[-dirty] (no reachable tag)  -> 0.0.0~<sha>[.dirty]

    The `~` separator makes prerelease/dirty versions sort lower than
    the bare tag in both deb and rpm version comparison rules.
    """
    if build_tag.startswith('v'):
        v = build_tag[1:]
        if '-' in v:
            tag, rest = v.split('-', 1)
            return f'{tag}~{rest.replace("-", ".")}'
        return v
    return f'0.0.0~{build_tag.replace("-", ".")}'


def purge_artifacts(release_path: Path, goos: str, goarch: str) -> None:
    """Remove prior build artifacts for this target."""
    names = [
        f'certdx_{goos}_{goarch}',
        f'caddy_certdx_{goos}_{goarch}',
    ]
    for name in names:
        d = release_path / name
        if d.is_dir():
            shutil.rmtree(d)
        for ext in ('.tar.gz', '.zip'):
            f = release_path / f'{name}{ext}'
            if f.exists():
                f.unlink()
    # deb/rpm filenames use packager-specific arch tokens that differ
    # from goarch (arm -> armhf / armv7hl), so iterate explicitly.
    if goos == 'linux' and goarch in NFPM_ARCH_MAP:
        _, deb_arch, rpm_arch = NFPM_ARCH_MAP[goarch]
        for f in release_path.glob(f'certdx_*_{deb_arch}.deb'):
            f.unlink()
        for f in release_path.glob(f'certdx-*.{rpm_arch}.rpm'):
            f.unlink()


def copy_release_files(repo_root: Path, output_dir: Path,
                       file_list: list[str]) -> None:
    """Copy files from repo_root into output_dir, preserving subdirectory structure."""
    for entry in file_list:
        src = repo_root / entry
        dst = output_dir / entry
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)


def build_certdx(repo_root: Path, output_dir: Path,
                 goos: str, goarch: str, dev_mode: bool,
                 build_tag: str, build_time: str) -> None:
    # Symbol-stripping ldflags. Dev builds keep symbols so stack traces
    # and debuggers stay useful; release builds strip them to shrink the
    # final binaries.
    strip_flags = '' if dev_mode else '-s -w '

    # Pin GOARM=7 so 32-bit ARM tarballs and the armhf deb/rpm ship the
    # same hard-float ELF.
    goarm_env = 'GOARM="7" ' if goarch == 'arm' else ''

    for exec_name, source in EXECS:
        ext = '.exe' if goos == 'windows' else ''
        subprocess.run(
            f'''cd {repo_root / source} && '''
            f'''env GOOS="{goos}" GOARCH="{goarch}" {goarm_env}CGO_ENABLED=0 '''
            f'''go build -ldflags="{strip_flags}'''
            f'''-X main.buildTag={build_tag} -X 'main.buildDate={build_time}'" '''
            f'''-o {output_dir}/certdx_{exec_name}{ext}''',
            shell=True, check=True,
        )

    if not dev_mode:
        copy_release_files(repo_root, output_dir, CERTDX_COPY)


def build_caddy(repo_root: Path, output_dir: Path,
                goos: str, goarch: str, dev_mode: bool,
                xcaddy_exec: Path) -> None:
    plugin = 'pkg.para.party/certdx/exec/caddytls'
    ext = '.exe' if goos == 'windows' else ''

    env = {
        'GOOS': goos,
        'GOARCH': goarch,
        'CGO_ENABLED': '0',
    }
    if goarch == 'arm':
        env['GOARM'] = '7'

    cmd = [str(xcaddy_exec), 'build',
           '--output', f'{output_dir}/caddy{ext}']

    if dev_mode:
        # Local source replacement for testing unreleased changes.
        # GOWORK=off prevents workspace mode from overriding --replace.
        # XCADDY_DEBUG=1 keeps debug symbols and disables optimisation.
        env['GOWORK'] = 'off'
        env['XCADDY_DEBUG'] = '1'
        cmd += ['--with', f'{plugin}={repo_root / "exec" / "caddytls"}',
                '--replace', f'pkg.para.party/certdx={repo_root}']
    else:
        # Release builds fetch the published module from the Go proxy.
        cmd += ['--with', plugin]

    subprocess.run(cmd, env={**os.environ, **env}, check=True)

    if not dev_mode:
        copy_release_files(repo_root, output_dir, CADDY_COPY)


def package_deb_rpm(repo_root: Path, release_path: Path,
                    goarch: str, build_tag: str,
                    nfpm_exec: Path) -> None:
    """Produce .deb and .rpm for the staged linux/<goarch> build.

    nfpm v2 does not env-var-substitute `contents.src` paths, so we
    render `release/nfpm.yaml` ourselves with string.Template before
    invoking nfpm. The rendered config goes to a per-arch sibling file
    so concurrent matrix builds don't race on a shared name. Reads
    binaries from release/certdx_linux_<goarch>/ and assets from the
    repo root via paths in the YAML; must run before
    package_artifacts(), which deletes the staging directory.
    """
    arch, _, _ = NFPM_ARCH_MAP[goarch]
    template_path = release_path / 'nfpm.yaml'
    rendered = string.Template(template_path.read_text()).substitute(
        VERSION=nfpm_version(build_tag),
        ARCH=arch,
        GOARCH=goarch,
    )
    rendered_path = release_path / f'.nfpm-{goarch}.yaml'
    rendered_path.write_text(rendered)
    try:
        for packager in ('deb', 'rpm'):
            subprocess.run(
                [str(nfpm_exec), 'pkg',
                 '--packager', packager,
                 '--config', str(rendered_path),
                 '--target', str(release_path)],
                cwd=str(repo_root),
                check=True,
            )
    finally:
        rendered_path.unlink()


def package_artifacts(output_dir: Path, output_dir_caddy: Path,
                      goos: str) -> None:
    fmt = 'zip' if goos == 'windows' else 'gztar'
    for d in (output_dir, output_dir_caddy):
        shutil.make_archive(str(d), fmt, root_dir=d.parent, base_dir=d.name)
        shutil.rmtree(d)


def main() -> None:
    doc_lines = (__doc__ or "").strip().splitlines()
    parser = argparse.ArgumentParser(
        description=doc_lines[0] if doc_lines else ""
    )
    parser.add_argument('goos', nargs='?',
                        help="target GOOS (default: `go env GOOS`)")
    parser.add_argument('goarch', nargs='?',
                        help="target GOARCH (default: `go env GOARCH`)")
    parser.add_argument('--dev', action='store_true',
                        help="dev build: keep debug symbols, skip config/license copy, leave binaries unarchived")
    args = parser.parse_args()

    if args.goos and args.goarch:
        goos, goarch = args.goos, args.goarch
    elif args.goos or args.goarch:
        parser.error("goos and goarch must be passed together")
    else:
        goos, goarch = host_target()

    dev_mode = args.dev

    # Derive a version tag from `git describe`. Falls back to the bare
    # commit hash when no annotated tag is reachable.
    build_tag = subprocess.run(
        ['git', 'describe', '--tags', '--always', '--dirty', '--match', 'v[0-9]*'],
        check=True, capture_output=True,
    ).stdout.decode().strip()

    build_time = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M %Z')

    release_path = Path(__file__).resolve().parent
    repo_root = release_path.parent
    os.chdir(release_path)

    purge_artifacts(release_path, goos, goarch)

    xcaddy_exec = find_xcaddy()

    output_dir = release_path / f'certdx_{goos}_{goarch}'
    output_dir_caddy = release_path / f'caddy_certdx_{goos}_{goarch}'

    build_certdx(repo_root, output_dir,
                 goos, goarch, dev_mode, build_tag, build_time)
    build_caddy(repo_root, output_dir_caddy,
                goos, goarch, dev_mode, xcaddy_exec)

    if dev_mode:
        print(f"Dev build ready at {output_dir.relative_to(repo_root)}/"
              f" and {output_dir_caddy.relative_to(repo_root)}/")
        return

    # Build .deb/.rpm before tarballing — package_artifacts deletes
    # the staging dir that nfpm reads binaries from.
    if goos == 'linux' and goarch in NFPM_ARCH_MAP:
        nfpm_exec = find_nfpm()
        package_deb_rpm(repo_root, release_path, goarch, build_tag, nfpm_exec)

    package_artifacts(output_dir, output_dir_caddy, goos)


if __name__ == '__main__':
    main()
