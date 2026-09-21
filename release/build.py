#!/usr/bin/env python3
"""Build certdx release artifacts and Docker images.

Usage:
    python3 build.py <command> [<goos> <goarch>] [--dev] [--archive]

Commands:
    release   Build and archive certdx and Caddy, plus Linux packages.
    certdx    Build certdx_server, certdx_client, and certdx_tools.
    caddy     Build Caddy with the certdx plugin.
    packages  Build Linux deb and rpm packages.
    docker    Build a Linux Docker image.

GOOS and GOARCH default to the host target. Docker always defaults to Linux
with the host architecture. Pass --dev to retain debug information and build
the Caddy plugin from the local checkout. The certdx and caddy commands also
accept --archive to include release files and archive their output.
"""

from __future__ import annotations

import argparse
import datetime
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shlex
import shutil
import string
import subprocess
import sys
import tempfile


CERTDX_COPY = (
    'config/client_config.toml',
    'config/client_config_full.toml',
    'config/server_config.toml',
    'config/server_config_full.toml',
    'systemd-service/certdx-client.service',
    'systemd-service/certdx-server.service',
    'LICENSE',
)

CADDY_COPY = (
    'config/Caddyfile_full',
    'LICENSE',
)

EXECUTABLES = (
    ('server', 'exec/server'),
    ('client', 'exec/client'),
    ('tools', 'exec/tools'),
)

# GOARCH -> (nfpm arch token, deb filename arch, rpm filename arch).
PACKAGE_ARCHES = {
    'amd64': ('amd64', 'amd64', 'x86_64'),
    'arm64': ('arm64', 'arm64', 'aarch64'),
    'arm': ('arm7', 'armhf', 'armv7hl'),
}

DOCKER_PLATFORMS = {
    'amd64': 'linux/amd64',
    'arm64': 'linux/arm64',
    'arm': 'linux/arm/v7',
}

DEBUG_GCFLAGS = 'all=-N -l'
DOCKER_TAG = re.compile(r'^[\w][\w.-]{0,127}$')


class BuildError(RuntimeError):
    """A concise error that can be shown without a traceback."""


@dataclass(frozen=True)
class Platform:
    goos: str
    goarch: str

    @property
    def executable_suffix(self) -> str:
        return '.exe' if self.goos == 'windows' else ''

    @property
    def archive_format(self) -> str:
        return 'zip' if self.goos == 'windows' else 'gztar'

    def environment(self) -> dict[str, str]:
        env = {
            'GOOS': self.goos,
            'GOARCH': self.goarch,
            'CGO_ENABLED': '0',
        }
        if self.goarch == 'arm':
            env['GOARM'] = '7'
        return env


@dataclass(frozen=True)
class BuildContext:
    repo_root: Path
    release_dir: Path
    platform: Platform
    dev: bool
    archive: bool
    build_tag: str
    build_time: str


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture_output: bool = False,
) -> str:
    """Run a command with consistent logging and environment handling."""
    print(f'+ {shlex.join(command)}')
    completed = subprocess.run(
        command,
        cwd=cwd,
        env={**os.environ, **env} if env else None,
        check=True,
        capture_output=capture_output,
        text=True,
    )
    return completed.stdout.strip() if capture_output else ''


def find_tool(name: str, install_command: str, *, go_tool: bool = False) -> str:
    executable = shutil.which(name)
    if executable:
        return executable

    if go_tool:
        fallback = Path.home() / 'go' / 'bin' / name
        if fallback.is_file():
            return str(fallback)

    raise BuildError(
        f'{name} is not installed; install it with `{install_command}`'
    )


def find_container_engine() -> str:
    for engine in ('docker', 'podman'):
        if executable := shutil.which(engine):
            return executable
    raise BuildError('docker or podman is required to build container images')


def host_target() -> Platform:
    return Platform(
        run(['go', 'env', 'GOOS'], capture_output=True),
        run(['go', 'env', 'GOARCH'], capture_output=True),
    )


def resolve_platform(args: argparse.Namespace, parser: argparse.ArgumentParser) -> Platform:
    if bool(args.goos) != bool(args.goarch):
        parser.error('goos and goarch must be passed together')
    if args.goos:
        return Platform(args.goos, args.goarch)

    host = host_target()
    if args.command == 'docker':
        return Platform('linux', host.goarch)
    return host


def build_tag(repo_root: Path) -> str:
    return run(
        ['git', 'describe', '--tags', '--always', '--dirty', '--match', 'v[0-9]*'],
        cwd=repo_root,
        capture_output=True,
    )


def build_time() -> str:
    return datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M %Z')


def nfpm_version(tag: str) -> str:
    """Convert git describe output to a deb/rpm-friendly version."""
    if tag.startswith('v'):
        version = tag[1:]
        if '-' in version:
            release, rest = version.split('-', 1)
            return f'{release}~{rest.replace("-", ".")}'
        return version
    return f'0.0.0~{tag.replace("-", ".")}'


def certdx_dir(context: BuildContext) -> Path:
    target = context.platform
    return context.release_dir / f'certdx_{target.goos}_{target.goarch}'


def caddy_dir(context: BuildContext) -> Path:
    target = context.platform
    return context.release_dir / f'caddy_certdx_{target.goos}_{target.goarch}'


def remove_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def clean_staging(path: Path) -> None:
    remove_path(path)
    remove_path(path.with_suffix('.zip'))
    remove_path(Path(f'{path}.tar.gz'))


def clean_packages(context: BuildContext) -> None:
    arches = PACKAGE_ARCHES.get(context.platform.goarch)
    if not arches:
        return
    _, deb_arch, rpm_arch = arches
    for artifact in context.release_dir.glob(f'certdx_*_{deb_arch}.deb'):
        artifact.unlink()
    for artifact in context.release_dir.glob(f'certdx-*.{rpm_arch}.rpm'):
        artifact.unlink()


def copy_release_files(context: BuildContext, output_dir: Path, files: tuple[str, ...]) -> None:
    for entry in files:
        source = context.repo_root / entry
        destination = output_dir / entry
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            shutil.copy2(source, destination)


def linker_flags(context: BuildContext) -> str:
    flags = [] if context.dev else ['-s', '-w']
    flags.extend((
        '-X', f'main.buildTag={context.build_tag}',
        '-X', f'main.buildDate={context.build_time}',
    ))
    return ' '.join(shlex.quote(flag) for flag in flags)


def build_certdx(context: BuildContext, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for executable, source in EXECUTABLES:
        command = ['go', 'build']
        if context.dev:
            command.extend(('-gcflags', DEBUG_GCFLAGS))
        command.extend((
            '-ldflags', linker_flags(context),
            '-o', str(output_dir / f'certdx_{executable}{context.platform.executable_suffix}'),
        ))
        run(
            command,
            cwd=context.repo_root / source,
            env=context.platform.environment(),
        )


def build_caddy(context: BuildContext, output_dir: Path) -> None:
    xcaddy = find_tool(
        'xcaddy',
        'go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest',
        go_tool=True,
    )
    plugin = 'pkg.para.party/certdx/exec/caddytls'
    env = context.platform.environment()
    command = [
        xcaddy,
        'build',
        '--output',
        str(output_dir / f'caddy{context.platform.executable_suffix}'),
    ]

    if context.dev:
        env.update({'GOWORK': 'off', 'XCADDY_DEBUG': '1'})
        command.extend((
            '--with', f'{plugin}={context.repo_root / "exec" / "caddytls"}',
            '--replace', f'pkg.para.party/certdx={context.repo_root}',
        ))
    else:
        command.extend(('--with', plugin))

    output_dir.mkdir(parents=True, exist_ok=True)
    run(command, env=env)


def build_packages(context: BuildContext, staging_dir: Path) -> None:
    nfpm = find_tool(
        'nfpm',
        'go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest',
        go_tool=True,
    )
    package_arch, _, _ = PACKAGE_ARCHES[context.platform.goarch]
    template = string.Template((context.release_dir / 'nfpm.yaml').read_text())
    rendered = template.substitute(
        VERSION=nfpm_version(context.build_tag),
        ARCH=package_arch,
        STAGING=staging_dir.relative_to(context.repo_root).as_posix(),
    )

    config_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            prefix='.nfpm-',
            suffix='.yaml',
            dir=context.release_dir,
            delete=False,
        ) as config:
            config.write(rendered)
            config_path = Path(config.name)

        for packager in ('deb', 'rpm'):
            run(
                [
                    nfpm,
                    'pkg',
                    '--packager', packager,
                    '--config', str(config_path),
                    '--target', str(context.release_dir),
                ],
                cwd=context.repo_root,
            )
    finally:
        if config_path:
            config_path.unlink(missing_ok=True)


def archive(path: Path, platform: Platform) -> None:
    shutil.make_archive(
        str(path),
        platform.archive_format,
        root_dir=path.parent,
        base_dir=path.name,
    )
    shutil.rmtree(path)


def command_certdx(context: BuildContext) -> None:
    output_dir = certdx_dir(context)
    clean_staging(output_dir)
    build_certdx(context, output_dir)
    if context.archive:
        copy_release_files(context, output_dir, CERTDX_COPY)
        archive(output_dir, context.platform)


def command_caddy(context: BuildContext) -> None:
    output_dir = caddy_dir(context)
    clean_staging(output_dir)
    build_caddy(context, output_dir)
    if context.archive:
        copy_release_files(context, output_dir, CADDY_COPY)
        archive(output_dir, context.platform)


def command_packages(context: BuildContext) -> None:
    validate_package_platform(context.platform)
    output_dir = certdx_dir(context)
    clean_staging(output_dir)
    clean_packages(context)
    build_certdx(context, output_dir)
    build_packages(context, output_dir)


def command_release(context: BuildContext) -> None:
    certdx_output = certdx_dir(context)
    caddy_output = caddy_dir(context)
    clean_staging(certdx_output)
    clean_staging(caddy_output)

    build_certdx(context, certdx_output)
    copy_release_files(context, certdx_output, CERTDX_COPY)
    build_caddy(context, caddy_output)
    copy_release_files(context, caddy_output, CADDY_COPY)

    if context.platform.goos == 'linux' and context.platform.goarch in PACKAGE_ARCHES:
        clean_packages(context)
        build_packages(context, certdx_output)

    archive(certdx_output, context.platform)
    archive(caddy_output, context.platform)


def command_docker(context: BuildContext) -> None:
    validate_docker_platform(context.platform)
    engine = find_container_engine()
    image_tag = context.build_tag + ('-dev' if context.dev else '')
    if not DOCKER_TAG.fullmatch(image_tag):
        raise BuildError(f'git build tag is not a valid Docker tag: {image_tag!r}')

    staging_dir = context.repo_root / '.container-build'
    remove_path(staging_dir)
    try:
        build_certdx(context, staging_dir)
        run([
            engine,
            'build',
            '--platform', DOCKER_PLATFORMS[context.platform.goarch],
            '--tag', f'paraparty/certdx:{image_tag}',
            str(context.repo_root),
        ])
    finally:
        remove_path(staging_dir)


def validate_package_platform(platform: Platform) -> None:
    if platform.goos != 'linux' or platform.goarch not in PACKAGE_ARCHES:
        arches = ','.join(PACKAGE_ARCHES)
        raise BuildError(
            f'packages supports linux/{{{arches}}} only, '
            f'got {platform.goos}/{platform.goarch}'
        )


def validate_docker_platform(platform: Platform) -> None:
    if platform.goos != 'linux' or platform.goarch not in DOCKER_PLATFORMS:
        arches = ','.join(DOCKER_PLATFORMS)
        raise BuildError(
            f'docker supports linux/{{{arches}}} only, '
            f'got {platform.goos}/{platform.goarch}'
        )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest='command', required=True)
    descriptions = {
        'release': 'build archives and supported Linux packages',
        'certdx': 'build the certdx executables',
        'caddy': 'build Caddy with the certdx plugin',
        'packages': 'build Linux deb and rpm packages',
        'docker': 'build a Linux Docker image',
    }
    for name, description in descriptions.items():
        command_parser = subparsers.add_parser(name, help=description)
        command_parser.add_argument('goos', nargs='?', help='target GOOS')
        command_parser.add_argument('goarch', nargs='?', help='target GOARCH')
        dev_help = 'keep debug information'
        if name in {'release', 'caddy'}:
            dev_help += ' and use local Caddy plugin sources'
        command_parser.add_argument(
            '-d',
            '--dev',
            action='store_true',
            help=dev_help,
        )
        if name in {'certdx', 'caddy'}:
            command_parser.add_argument(
                '-a',
                '--archive',
                action='store_true',
                help='include release files and archive the result',
            )
    return parser


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()
    platform = resolve_platform(args, parser)
    if args.command == 'packages':
        validate_package_platform(platform)
    elif args.command == 'docker':
        validate_docker_platform(platform)

    release_dir = Path(__file__).resolve().parent
    repo_root = release_dir.parent
    context = BuildContext(
        repo_root=repo_root,
        release_dir=release_dir,
        platform=platform,
        dev=args.dev,
        archive=getattr(args, 'archive', False),
        build_tag=build_tag(repo_root),
        build_time=build_time(),
    )

    commands = {
        'release': command_release,
        'certdx': command_certdx,
        'caddy': command_caddy,
        'packages': command_packages,
        'docker': command_docker,
    }
    commands[args.command](context)
    print(
        f'Built {args.command} for {platform.goos}/{platform.goarch} '
        f'({context.build_tag})'
    )
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BuildError as error:
        sys.exit(f'Error: {error}')
    except subprocess.CalledProcessError as error:
        sys.exit(f'Error: command failed with exit status {error.returncode}')
