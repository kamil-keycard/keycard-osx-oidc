#!/bin/bash
# Uninstall keycard-osx-oidc.
#
# Usage:
#   sudo ./packaging/uninstall.sh           # keep config + signing keys
#   sudo ./packaging/uninstall.sh --purge   # also remove config + keys + log

set -euo pipefail

LABEL="com.keycard.osx-oidcd"
DAEMON_INSTALL="/usr/local/sbin/keycard-osx-oidcd"
CLI_INSTALL="/usr/local/bin/keycard-osx-oidc"
PLIST_DEST="/Library/LaunchDaemons/$LABEL.plist"
CONFIG_DIR="/etc/keycard-osx-oidcd"
STATE_DIR="/var/db/keycard-osx-oidcd"
LOG_FILE="/var/log/keycard-osx-oidcd.log"
SOCKET="/var/run/keycard-osx-oidcd.sock"

if [[ "$EUID" -ne 0 ]]; then
    echo "uninstall.sh must be run as root (use sudo)" >&2
    exit 1
fi

PURGE=0
if [[ "${1:-}" == "--purge" ]]; then
    PURGE=1
fi

echo "[uninstall] stopping daemon"
launchctl bootout "system/$LABEL" 2>/dev/null || true

echo "[uninstall] resetting tailscale serve/funnel"
tailscale serve reset 2>/dev/null || true
tailscale funnel reset 2>/dev/null || true

echo "[uninstall] removing files"
rm -f "$PLIST_DEST"
rm -f "$DAEMON_INSTALL"
rm -f "$CLI_INSTALL"
rm -f "$SOCKET"

if [[ "$PURGE" -eq 1 ]]; then
    echo "[uninstall] --purge: removing config, keys and log"
    echo "           !! This invalidates every previously issued token !!"
    rm -rf "$CONFIG_DIR" "$STATE_DIR" "$LOG_FILE"
else
    echo "[uninstall] preserving $CONFIG_DIR and $STATE_DIR"
    echo "[uninstall] re-run with --purge to remove them"
fi

echo "[uninstall] done"
