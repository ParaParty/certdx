#!/bin/sh
# postremove — runs after files are removed on uninstall or upgrade.
#
# Reload systemd unit definitions. Intentionally does NOT delete
# /etc/certdx/ or /var/lib/certdx/: those may contain CA private
# keys, ACME account keys, and the cert cache that the user cannot
# regenerate (Let's Encrypt rate limits). Operators who really want a
# clean wipe should `rm -rf` them by hand.

set -e

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
