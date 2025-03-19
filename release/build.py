#! /usr/bin/python3

import subprocess
import datetime
import os
import shutil

subprocess.run("rm -r ./certdx_* ./caddy_certdx_*", shell=True)

commitId = subprocess.run("git rev-parse --short HEAD", shell=True, capture_output=True)
commitId = commitId.stdout.decode().strip()

time = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M')
cwd = os.getcwd()

targets = [
    ['linux',   'amd64'],
    ['linux',   'arm'],
    ['linux',   'arm64'],
    ['linux',   'mips'],
    ['linux',   'mipsle'],
    ['windows', 'amd64'],
]

execs = [
    ['server', 'exec/server'],
    ['client', 'exec/client'],
    ['tools',  'exec/tools'],
]

copy = [
    'config',
    'systemd-service',
    'LICENSE',
]
copy = map(lambda x: f'../{x}', copy)
copy = ' '.join(copy)

copy_caddy = [
    'exec/caddytls/readme.md',
    'LICENSE',
]
copy_caddy = map(lambda x: f'../{x}', copy_caddy)
copy_caddy = ' '.join(copy_caddy)

# find xcaddy executable in PATH
xcaddy_exec = shutil.which("xcaddy")
if not xcaddy_exec:
    # if not found, try finding it at go bin
    xcaddy_exec = os.path.expanduser("~/go/bin/xcaddy")

if not os.path.isfile(xcaddy_exec):
    print("Error: xcaddy is not installed. Please install xcaddy before building caddy with certdx.")
    xcaddy_exec = None

for goos, goarch in targets:
    output_dir = f'certdx_{goos}_{goarch}'
    for exec_name, source in execs:
        subprocess.run(
            f'''cd ../{source} && '''
            f'''env GOOS="{goos}" GOARCH="{goarch}" CGO_ENABLED=0 '''
            f'''go build -ldflags="-s -w '''
            f'''-X main.buildCommit={commitId} -X \'main.buildDate={time}\'" '''
            f'''-o {cwd}/{output_dir}/certdx_{exec_name}{".exe" if goos == "windows" else ""} '''
            , shell=True
        )
    subprocess.run(f"cp -r {copy} {output_dir}", shell=True)
    subprocess.run(f"zip -r {output_dir}.zip {output_dir}", shell=True)
    subprocess.run(f"rm -r {output_dir}", shell=True)

    # build caddy with certdx
    if xcaddy_exec:
        output_dir_caddy = f'caddy_certdx_{goos}_{goarch}'
        subprocess.run(
            f'''env GOOS="{goos}" GOARCH="{goarch}" CGO_ENABLED=0 '''
            f'''{xcaddy_exec} build '''
            f'''--with pkg.para.party/certdx/exec/caddytls=../exec/caddytls '''
            f'''--replace pkg.para.party/certdx=../ '''
            f'''--output {output_dir_caddy}/caddy{".exe" if goos == "windows" else ""}'''
            , shell=True
        )
        subprocess.run(f"cp -r {copy_caddy} {output_dir_caddy}", shell=True)
        subprocess.run(f"zip -r {output_dir_caddy}.zip {output_dir_caddy}", shell=True)
        subprocess.run(f"rm -r {output_dir_caddy}", shell=True)

