#! /usr/bin/python3

import subprocess
import datetime
import os
import shutil

commitId = subprocess.run("git rev-parse --short HEAD", shell=True, check=True, capture_output=True)
commitId = commitId.stdout.decode().strip()

time = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M')

release_path = os.path.abspath(f'{__file__}/../')
os.chdir(release_path)

subprocess.run(f"rm -r ./certdx_* ./caddy_certdx_*", shell=True)

# goos, goarch
targets = [
    ['linux',   'amd64'],
    ['linux',   'arm'],
    ['linux',   'arm64'],
    ['linux',   'mips'],
    ['linux',   'mipsle'],
    ['darwin',  'arm64'],
    ['windows', 'amd64'],
]

# executable, source
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
            f'''-o {release_path}/{output_dir}/certdx_{exec_name}{".exe" if goos == "windows" else ""} '''
            , shell=True, check=True
        )
    subprocess.run(f"cp -r {copy} {output_dir}", shell=True, check=True)
    if goos == "windows":
        subprocess.run(f"zip -r {output_dir}.zip {output_dir}", shell=True, check=True)
    else:
        subprocess.run(f"tar -czf {output_dir}.tar.gz {output_dir}", shell=True, check=True)
    subprocess.run(f"rm -r {output_dir}", shell=True, check=True)

    # build caddy with certdx
    if xcaddy_exec:
        output_dir_caddy = f'caddy_certdx_{goos}_{goarch}'
        subprocess.run(
            f'''env GOOS="{goos}" GOARCH="{goarch}" CGO_ENABLED=0 '''
            f'''{xcaddy_exec} build '''
            f'''--with pkg.para.party/certdx/exec/caddytls=../exec/caddytls '''
            f'''--replace pkg.para.party/certdx=../ '''
            f'''--output {output_dir_caddy}/caddy{".exe" if goos == "windows" else ""}'''
            , shell=True, check=True
        )
        subprocess.run(f"cp -r {copy_caddy} {output_dir_caddy}", shell=True, check=True)
        if goos == "windows":
            subprocess.run(f"zip -r {output_dir_caddy}.zip {output_dir_caddy}", shell=True, check=True)
        else:
            subprocess.run(f"tar -czf {output_dir_caddy}.tar.gz {output_dir_caddy}", shell=True, check=True)
        subprocess.run(f"rm -r {output_dir_caddy}", shell=True, check=True)
