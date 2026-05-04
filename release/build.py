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
import shutil
import subprocess
import sys


def host_target() -> tuple[str, str]:
    goos = subprocess.run(
        ['go', 'env', 'GOOS'], check=True, capture_output=True,
    ).stdout.decode().strip()
    goarch = subprocess.run(
        ['go', 'env', 'GOARCH'], check=True, capture_output=True,
    ).stdout.decode().strip()
    return goos, goarch


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

    commit_id = subprocess.run(
        "git rev-parse --short HEAD", shell=True, check=True, capture_output=True,
    ).stdout.decode().strip()

    build_time = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M')

    release_path = os.path.abspath(f'{__file__}/../')
    os.chdir(release_path)

    # Purge any prior artifacts for this target so the build is clean.
    subprocess.run(
        f"rm -rf ./certdx_{goos}_{goarch} ./certdx_{goos}_{goarch}.tar.gz "
        f"./certdx_{goos}_{goarch}.zip ./caddy_certdx_{goos}_{goarch} "
        f"./caddy_certdx_{goos}_{goarch}.tar.gz ./caddy_certdx_{goos}_{goarch}.zip",
        shell=True,
    )

    # executable, source
    execs = [
        ['server', 'exec/server'],
        ['client', 'exec/client'],
        ['tools',  'exec/tools'],
    ]

    copy = ' '.join(f'../{x}' for x in [
        'config',
        'systemd-service',
        'LICENSE',
    ])
    copy_caddy = ' '.join(f'../{x}' for x in [
        'exec/caddytls/readme.md',
        'LICENSE',
    ])

    # Symbol-stripping ldflags. Dev builds keep symbols so stack traces
    # and debuggers stay useful; release builds strip them to shrink the
    # final binaries.
    strip_flags = '' if dev_mode else '-s -w '

    xcaddy_exec = shutil.which("xcaddy")
    if not xcaddy_exec:
        # Not on PATH — try the conventional go install location.
        xcaddy_exec = os.path.expanduser("~/go/bin/xcaddy")
    if not os.path.isfile(xcaddy_exec):
        sys.exit("Error: xcaddy is not installed. Install it before running build.py "
                 "(`go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest`).")

    output_dir = f'certdx_{goos}_{goarch}'
    for exec_name, source in execs:
        subprocess.run(
            f'''cd ../{source} && '''
            f'''env GOOS="{goos}" GOARCH="{goarch}" CGO_ENABLED=0 '''
            f'''go build -ldflags="{strip_flags}'''
            f'''-X main.buildCommit={commit_id} -X \'main.buildDate={build_time}\'" '''
            f'''-o {release_path}/{output_dir}/certdx_{exec_name}{".exe" if goos == "windows" else ""} ''',
            shell=True, check=True,
        )
    if not dev_mode:
        # Dev mode keeps the dir binary-only — config / systemd / LICENSE
        # belong in release archives, not in a debugger workspace.
        subprocess.run(f"cp -r {copy} {output_dir}", shell=True, check=True)

    output_dir_caddy = f'caddy_certdx_{goos}_{goarch}'
    # XCADDY_DEBUG=1 swaps xcaddy's default `-ldflags -w -s -trimpath` for
    # `-gcflags all=-N -l`, so the dev caddy binary is unstripped and
    # optimizer-friendly to attach a debugger to.
    caddy_env_extra = 'XCADDY_DEBUG=1 ' if dev_mode else ''
    # GOWORK=off — xcaddy's temp build dir is created under release/, which
    # lives inside the repo's go.work. Without this, Go enters workspace
    # mode, finds ./exec/caddytls in the workspace, and bypasses the
    # --replace directives we just passed (occasionally leading to
    # "cannot find module" surprises). Setting GOWORK=off keeps xcaddy
    # in module mode where the --replace flags actually take effect.
    subprocess.run(
        f'''env GOWORK=off {caddy_env_extra}GOOS="{goos}" GOARCH="{goarch}" CGO_ENABLED=0 '''
        f'''{xcaddy_exec} build '''
        f'''--with pkg.para.party/certdx/exec/caddytls=../exec/caddytls '''
        f'''--replace pkg.para.party/certdx=../ '''
        f'''--output {output_dir_caddy}/caddy{".exe" if goos == "windows" else ""}''',
        shell=True, check=True,
    )
    if not dev_mode:
        subprocess.run(f"cp -r {copy_caddy} {output_dir_caddy}", shell=True, check=True)

    if dev_mode:
        print(f"Dev build ready at release/{output_dir}/ and release/{output_dir_caddy}/")
        return

    if goos == "windows":
        subprocess.run(f"zip -r {output_dir}.zip {output_dir}", shell=True, check=True)
        subprocess.run(f"zip -r {output_dir_caddy}.zip {output_dir_caddy}", shell=True, check=True)
    else:
        subprocess.run(f"tar -czf {output_dir}.tar.gz {output_dir}", shell=True, check=True)
        subprocess.run(f"tar -czf {output_dir_caddy}.tar.gz {output_dir_caddy}", shell=True, check=True)
    subprocess.run(f"rm -r {output_dir} {output_dir_caddy}", shell=True, check=True)


if __name__ == '__main__':
    main()
