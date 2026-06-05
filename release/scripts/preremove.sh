#!/bin/sh
# preremove — runs before files are removed on uninstall or upgrade.
#
# Stop and disable the certdx services so an upgrade cleanly replaces
# the running binaries. Best-effort: ignore failures (e.g. when the
# package was installed without systemd, or the units were never
# enabled).

set -e

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --no-reload disable --now \
        certdx-server.service certdx-client.service >/dev/null 2>&1 || true
fi

exit 0
