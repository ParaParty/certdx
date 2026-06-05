#!/bin/sh
# postinstall — runs after files are unpacked on install or upgrade.
#
# Reload systemd unit definitions and print next-step instructions.
# Does NOT enable or start services: the FHS units require a
# hand-written /etc/certdx/{server,client}.toml that the user must
# create from the shipped *.example file.

set -e

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

cat <<'EOF'

certdx is installed.

Next steps:
  1. Copy and edit the relevant example config(s):
       cp /etc/certdx/server.toml.example /etc/certdx/server.toml
       cp /etc/certdx/client.toml.example /etc/certdx/client.toml
     (See server.toml.full.example / client.toml.full.example for
     every available option.)

  2. (server, mTLS only) Generate mTLS material:
       certdx_tools make-ca
       certdx_tools make-server -n certdx-server -d <names>

  3. Enable and start the unit you need:
       systemctl enable --now certdx-server
       systemctl enable --now certdx-client

Documentation: https://github.com/ParaParty/certdx
EOF

exit 0
