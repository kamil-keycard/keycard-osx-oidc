#!/bin/bash
# Install keycard-osx-oidc on a macOS host.
#
# Usage:
#   sudo ./packaging/install.sh
#
# Idempotent. Safe to re-run after an upgrade. Preserves config and signing
# keys across re-runs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

LABEL="com.keycard.osx-oidcd"
DAEMON_BIN_NAME="keycard-osx-oidcd"
CLI_BIN_NAME="keycard-osx-oidc"
DAEMON_INSTALL="/usr/local/sbin/$DAEMON_BIN_NAME"
CLI_INSTALL="/usr/local/bin/$CLI_BIN_NAME"
PLIST_SRC="$SCRIPT_DIR/launchd/$LABEL.plist"
PLIST_DEST="/Library/LaunchDaemons/$LABEL.plist"
CONFIG_DIR="/etc/keycard-osx-oidcd"
CONFIG_FILE="$CONFIG_DIR/config.toml"
CONFIG_EXAMPLE="$SCRIPT_DIR/config.example.toml"
STATE_DIR="/var/db/keycard-osx-oidcd"
KEYS_DIR="$STATE_DIR/keys"
LOG_FILE="/var/log/keycard-osx-oidcd.log"

if [[ "$EUID" -ne 0 ]]; then
    echo "install.sh must be run as root (use sudo)" >&2
    exit 1
fi

build_release() {
    if [[ -x "$REPO_ROOT/target/release/$DAEMON_BIN_NAME" ]] && \
       [[ -x "$REPO_ROOT/target/release/$CLI_BIN_NAME" ]]; then
        return
    fi
    echo "[install] release binaries missing, running 'cargo build --release'..."
    (cd "$REPO_ROOT" && cargo build --release)
}

build_release

echo "[install] stopping any existing daemon..."
launchctl bootout "system/$LABEL" 2>/dev/null || true

echo "[install] preparing install dirs"
# /usr/local/sbin and even /usr/local/bin can be missing on a fresh macOS,
# and BSD install(1) doesn't create the destination's parent directory. Make
# sure both bin dirs exist before we drop binaries into them.
install -d -m 0755 -o root -g wheel /usr/local/sbin
install -d -m 0755 -o root -g wheel /usr/local/bin
install -d -m 0755 -o root -g wheel /Library/LaunchDaemons

echo "[install] installing binaries"
install -m 0755 -o root -g wheel "$REPO_ROOT/target/release/$DAEMON_BIN_NAME" "$DAEMON_INSTALL"
install -m 0755 -o root -g wheel "$REPO_ROOT/target/release/$CLI_BIN_NAME"    "$CLI_INSTALL"

echo "[install] preparing state dirs"
install -d -m 0755 -o root -g wheel "$CONFIG_DIR"
install -d -m 0700 -o root -g wheel "$STATE_DIR"
install -d -m 0700 -o root -g wheel "$KEYS_DIR"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[install] writing default config $CONFIG_FILE"
    install -m 0644 -o root -g wheel "$CONFIG_EXAMPLE" "$CONFIG_FILE"
    echo
    echo "  >>> Edit $CONFIG_FILE and set 'issuer' to your Tailscale URL,"
    echo "  >>> then re-run this script (or 'launchctl kickstart -kp system/$LABEL')."
    echo
else
    echo "[install] config already present, leaving $CONFIG_FILE untouched"
fi

echo "[install] preparing log file"
touch "$LOG_FILE"
chown root:wheel "$LOG_FILE"
chmod 0644 "$LOG_FILE"

echo "[install] installing launchd plist"
install -m 0644 -o root -g wheel "$PLIST_SRC" "$PLIST_DEST"

if grep -q '^issuer = "https://CHANGE-ME' "$CONFIG_FILE" 2>/dev/null; then
    echo "[install] config still has placeholder issuer; not loading the daemon."
    echo "[install] edit $CONFIG_FILE then run:"
    echo "           sudo launchctl bootstrap system $PLIST_DEST"
    echo "           sudo launchctl enable system/$LABEL"
    echo "           sudo launchctl kickstart -kp system/$LABEL"
    exit 0
fi

echo "[install] loading launchd job"
launchctl bootstrap system "$PLIST_DEST"
launchctl enable "system/$LABEL"
launchctl kickstart -kp "system/$LABEL"

sleep 1
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    state="$(launchctl print system/$LABEL | awk -F'= *' '/[[:space:]]state =/ {print $2; exit}')"
    echo "[install] launchd reports state = $state"
fi

echo "[install] done. Tail logs with: sudo tail -f $LOG_FILE"
