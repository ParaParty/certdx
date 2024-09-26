#! /usr/bin/python3

import subprocess
import datetime

subprocess.run("rm -r ./certdx_*", shell=True)

commitId = subprocess.run("git rev-parse --short HEAD", shell=True, capture_output=True)
commitId = commitId.stdout.decode().strip()

time = datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M')

t = [['linux',   'amd64'],
     ['linux',   'arm'],
     ['linux',   'arm64'],
     ['linux',   'mips'],
     ['linux',   'mipsle'],
     ['windows', 'amd64'],
]

exec = [['server', 'exec/server'],
        ['client', 'exec/client'],
        ['tools',  'exec/tools'],
]

for o, a in t:
    dir = f'certdx_{o}_{a}'
    for e, s in exec:
        subprocess.run(
            f'''env GOOS="{o}" GOARCH="{a}" CGO_ENABLED=0 '''
            f'''go build -ldflags="-s -w '''
            f'''-X main.buildCommit={commitId} -X \'main.buildDate={time}\'" '''
            f'''-o {dir}/{e}{".exe" if o == "windows" else ""} '''
            f'''../{s}''', shell=True
        )
    subprocess.run(f"zip -r {dir}.zip {dir}", shell=True)
    subprocess.run(f"rm -r {dir}", shell=True)

