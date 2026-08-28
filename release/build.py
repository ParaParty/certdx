#! /usr/bin/python3
"""Build certdx / caddy_certdx artifacts for a single (goos, goarch).

Usage
-----

    python3 build.py <target> [<goos>] [<goarch>] [--dev] [--pack] [--output DIR]

`goos` and `goarch` are optional and default to the host platform
(`go env GOOS` / `go env GOARCH`). They must be set together.

Targets
-------

    release   certdx + caddy_certdx, with config / systemd-service / LICENSE
              copied in and archived to .tar.gz / .zip, plus .deb and .rpm on
              supported linux arches. This is what the release CI workflow
              runs, once per GOOS/GOARCH matrix entry.
    certdx    certdx_server / certdx_client / certdx_tools only.
    caddy     caddy with the certdx plugin only.
    packages  .deb and .rpm only; builds the certdx binaries they contain.
    docker    certdx binaries written flat into --output (default /out).
              Used by the Dockerfile builder stage.

Flags
-----

    --dev     keep symbols and disable optimisation/inlining so the binaries
              are debuggable (XCADDY_DEBUG=1 for the caddy build, which also
              builds the plugin from the local checkout instead of the proxy).
    --pack    `certdx` and `caddy` targets only: also copy the release files
              in and archive the staging directory, as `release` does.
    --output  base output directory. Defaults to `release/` (`/out` for the
              docker target).

Examples:

    python3 build.py release linux amd64     # full release pack for a target
    python3 build.py certdx                  # host binaries, no archive
    python3 build.py caddy --dev             # debuggable caddy from local src
    python3 build.py docker --output /out    # what the Dockerfile runs
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

# Disables optimisation and inlining so delve can resolve locals.
DEBUG_GCFLAGS = 'all=-N -l'

# What each target builds and emits. `flat` writes the binaries straight into
# the output directory instead of a `certdx_<goos>_<goarch>/` staging dir.
TARGETS = {
    'release':  {'certdx': True,  'caddy': True,  'pack': True,
                 'nfpm': True,  'flat': False, 'gowork': True},
    'certdx':   {'certdx': True,  'caddy': False, 'pack': False,
                 'nfpm': False, 'flat': False, 'gowork': True},
    'caddy':    {'certdx': False, 'caddy': True,  'pack': False,
                 'nfpm': False, 'flat': False, 'gowork': True},
    'packages': {'certdx': True,  'caddy': False, 'pack': False,
                 'nfpm': True,  'flat': False, 'gowork': True},
    'docker':   {'certdx': True,  'caddy': False, 'pack': False,
                 'nfpm': False, 'flat': True,  'gowork': False},
}

# Targets that accept --pack; the others either always pack or never can.
PACKABLE_TARGETS = ('certdx', 'caddy')


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


def purge_artifacts(plan: dict, output_base: Path,
                    goos: str, goarch: str) -> None:
    """Remove prior build artifacts for this target."""
    ext = '.exe' if goos == 'windows' else ''

    if plan['flat']:
        for exec_name, _ in EXECS:
            f = output_base / f'certdx_{exec_name}{ext}'
            if f.exists():
                f.unlink()
        return

    names = []
    if plan['certdx']:
        names.append(f'certdx_{goos}_{goarch}')
    if plan['caddy']:
        names.append(f'caddy_certdx_{goos}_{goarch}')
    for name in names:
        d = output_base / name
        if d.is_dir():
            shutil.rmtree(d)
        for suffix in ('.tar.gz', '.zip'):
            f = output_base / f'{name}{suffix}'
            if f.exists():
                f.unlink()

    # deb/rpm filenames use packager-specific arch tokens that differ
    # from goarch (arm -> armhf / armv7hl), so iterate explicitly.
    if plan['nfpm'] and goos == 'linux' and goarch in NFPM_ARCH_MAP:
        _, deb_arch, rpm_arch = NFPM_ARCH_MAP[goarch]
        for f in output_base.glob(f'certdx_*_{deb_arch}.deb'):
            f.unlink()
        for f in output_base.glob(f'certdx-*.{rpm_arch}.rpm'):
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
                 goos: str, goarch: str, dev: bool, gowork: bool,
                 build_tag: str, build_time: str) -> None:
    # Dev builds keep symbols and skip optimisation so stack traces and
    # debuggers stay useful; everything else strips to shrink the binaries.
    strip_flags = '' if dev else '-s -w '
    gcflags = f'-gcflags="{DEBUG_GCFLAGS}" ' if dev else ''

    # Pin GOARM=7 so 32-bit ARM tarballs and the armhf deb/rpm ship the
    # same hard-float ELF.
    goarm_env = 'GOARM="7" ' if goarch == 'arm' else ''
    gowork_env = '' if gowork else 'GOWORK="off" '

    output_dir.mkdir(parents=True, exist_ok=True)

    for exec_name, source in EXECS:
        ext = '.exe' if goos == 'windows' else ''
        subprocess.run(
            f'''cd {repo_root / source} && '''
            f'''env GOOS="{goos}" GOARCH="{goarch}" {goarm_env}{gowork_env}CGO_ENABLED=0 '''
            f'''go build {gcflags}-ldflags="{strip_flags}'''
            f'''-X main.buildTag={build_tag} -X 'main.buildDate={build_time}'" '''
            f'''-o {output_dir}/certdx_{exec_name}{ext}''',
            shell=True, check=True,
        )


def build_caddy(repo_root: Path, output_dir: Path,
                goos: str, goarch: str, dev: bool,
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

    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [str(xcaddy_exec), 'build',
           '--output', f'{output_dir}/caddy{ext}']

    if dev:
        # Local source replacement for testing unreleased changes.
        # GOWORK=off prevents workspace mode from overriding --replace.
        # XCADDY_DEBUG=1 keeps debug symbols and disables optimisation.
        env['GOWORK'] = 'off'
        env['XCADDY_DEBUG'] = '1'
        cmd += ['--with', f'{plugin}={repo_root / "exec" / "caddytls"}',
                '--replace', f'pkg.para.party/certdx={repo_root}']
    else:
        # Non-dev builds fetch the published module from the Go proxy.
        cmd += ['--with', plugin]

    subprocess.run(cmd, env={**os.environ, **env}, check=True)


def package_deb_rpm(repo_root: Path, release_path: Path, output_base: Path,
                    staging_dir: Path, goarch: str, build_tag: str,
                    nfpm_exec: Path) -> None:
    """Produce .deb and .rpm from the staged linux/<goarch> binaries.

    nfpm v2 does not env-var-substitute `contents.src` paths, so we
    render `release/nfpm.yaml` ourselves with string.Template before
    invoking nfpm. The rendered config goes to a per-arch sibling file
    so concurrent matrix builds don't race on a shared name. Must run
    before package_artifacts(), which deletes the staging directory.
    """
    arch, _, _ = NFPM_ARCH_MAP[goarch]
    template_path = release_path / 'nfpm.yaml'
    rendered = string.Template(template_path.read_text()).substitute(
        VERSION=nfpm_version(build_tag),
        ARCH=arch,
        STAGING=staging_dir.relative_to(repo_root).as_posix(),
    )
    rendered_path = release_path / f'.nfpm-{goarch}.yaml'
    rendered_path.write_text(rendered)
    try:
        for packager in ('deb', 'rpm'):
            subprocess.run(
                [str(nfpm_exec), 'pkg',
                 '--packager', packager,
                 '--config', str(rendered_path),
                 '--target', str(output_base)],
                cwd=str(repo_root),
                check=True,
            )
    finally:
        rendered_path.unlink()


def package_artifacts(dirs: list[Path], goos: str) -> None:
    fmt = 'zip' if goos == 'windows' else 'gztar'
    for d in dirs:
        shutil.make_archive(str(d), fmt, root_dir=d.parent, base_dir=d.name)
        shutil.rmtree(d)


def main() -> None:
    doc_lines = (__doc__ or "").strip().splitlines()
    parser = argparse.ArgumentParser(
        description=doc_lines[0] if doc_lines else ""
    )
    parser.add_argument('target', choices=list(TARGETS),
                        help="what to build")
    parser.add_argument('goos', nargs='?',
                        help="target GOOS (default: `go env GOOS`)")
    parser.add_argument('goarch', nargs='?',
                        help="target GOARCH (default: `go env GOARCH`)")
    parser.add_argument('--dev', action='store_true',
                        help="keep debug symbols and disable optimisation")
    parser.add_argument('--pack', action='store_true',
                        help=f"{'/'.join(PACKABLE_TARGETS)} targets: copy the "
                             "release files in and archive the result")
    parser.add_argument('--output', metavar='DIR',
                        help="base output directory (default: release/, "
                             "/out for the docker target)")
    args = parser.parse_args()

    if args.goos and args.goarch:
        goos, goarch = args.goos, args.goarch
    elif args.goos or args.goarch:
        parser.error("goos and goarch must be passed together")
    else:
        goos, goarch = host_target()

    plan = dict(TARGETS[args.target])
    if args.pack:
        if args.target not in PACKABLE_TARGETS:
            parser.error(f"--pack is only valid for the "
                         f"{'/'.join(PACKABLE_TARGETS)} targets")
        plan['pack'] = True

    release_path = Path(__file__).resolve().parent
    repo_root = release_path.parent

    if args.output:
        output_base = Path(args.output).resolve()
    elif plan['flat']:
        output_base = Path('/out')
    else:
        output_base = release_path

    build_deb_rpm = plan['nfpm'] and goos == 'linux' and goarch in NFPM_ARCH_MAP
    if args.target == 'packages' and not build_deb_rpm:
        parser.error(f"the packages target supports linux/"
                     f"{{{','.join(NFPM_ARCH_MAP)}}} only, "
                     f"got {goos}/{goarch}")
    if build_deb_rpm and not output_base.is_relative_to(repo_root):
        parser.error("deb/rpm packaging needs --output inside the repository "
                     "(nfpm resolves source paths relative to the repo root)")

    # Derive a version tag from `git describe`. Falls back to the bare
    # commit hash when no annotated tag is reachable.
    build_tag = subprocess.run(
        ['git', 'describe', '--tags', '--always', '--dirty', '--match', 'v[0-9]*'],
        cwd=str(repo_root), check=True, capture_output=True,
    ).stdout.decode().strip()

    build_time = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M %Z')

    output_base.mkdir(parents=True, exist_ok=True)
    purge_artifacts(plan, output_base, goos, goarch)

    certdx_dir = (output_base if plan['flat']
                  else output_base / f'certdx_{goos}_{goarch}')
    caddy_dir = output_base / f'caddy_certdx_{goos}_{goarch}'

    if plan['certdx']:
        build_certdx(repo_root, certdx_dir, goos, goarch, args.dev,
                     plan['gowork'], build_tag, build_time)
        if plan['pack']:
            copy_release_files(repo_root, certdx_dir, CERTDX_COPY)

    if plan['caddy']:
        build_caddy(repo_root, caddy_dir, goos, goarch, args.dev,
                    find_xcaddy())
        if plan['pack']:
            copy_release_files(repo_root, caddy_dir, CADDY_COPY)

    # Runs before package_artifacts, which deletes the staging directory
    # nfpm reads the binaries from.
    if build_deb_rpm:
        package_deb_rpm(repo_root, release_path, output_base, certdx_dir,
                        goarch, build_tag, find_nfpm())

    if plan['pack']:
        staged = []
        if plan['certdx']:
            staged.append(certdx_dir)
        if plan['caddy']:
            staged.append(caddy_dir)
        package_artifacts(staged, goos)

    print(f"Built {args.target} for {goos}/{goarch} "
          f"({build_tag}) in {output_base}")


if __name__ == '__main__':
    main()
