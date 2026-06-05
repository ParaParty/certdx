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

# Keep this message short: dnf5 truncates captured scriptlet output
# at a fixed ~512-byte buffer, so anything longer is clipped mid-line.
cat <<'EOF'

certdx is installed. Config examples live in /etc/certdx.

Setup guide: https://github.com/ParaParty/certdx/blob/main/docs/setup.md
EOF

exit 0
