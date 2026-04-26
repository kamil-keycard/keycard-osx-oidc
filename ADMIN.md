# keycard-osx-oidc Operator Runbook

This is the step-by-step guide for deploying, verifying, operating, and
uninstalling `keycard-osx-oidc` on a macOS host. Follow it top-to-bottom on
a fresh install.

## Filesystem layout (deployed)

| Path | Owner | Mode | Purpose |
|------|-------|------|---------|
| `/usr/local/sbin/keycard-osx-oidcd` | root:wheel | 0755 | daemon binary |
| `/usr/local/bin/keycard-osx-oidc` | root:wheel | 0755 | user CLI binary |
| `/Library/LaunchDaemons/com.keycard.osx-oidcd.plist` | root:wheel | 0644 | launchd job spec |
| `/etc/keycard-osx-oidcd/config.toml` | root:wheel | 0644 | issuer URL, allowed audiences, TTLs |
| `/var/db/keycard-osx-oidcd/keys/current.json` | root:wheel | 0600 | active signing key (JWK) |
| `/var/db/keycard-osx-oidcd/keys/previous.json` | root:wheel | 0600 | rotated-out public key (grace) |
| `/var/db/keycard-osx-oidcd/keys/meta.json` | root:wheel | 0644 | rotation timestamps |
| `/var/run/keycard-osx-oidcd.sock` | root:wheel | 0666 | UDS for token requests |
| `/var/log/keycard-osx-oidcd.log` | root:wheel | 0644 | combined stdout+stderr from launchd |

## 0. Prerequisites

- macOS 13 (Ventura) or newer, Apple Silicon or Intel.
- Administrator account on the Mac (`sudo` access).
- Rust toolchain to build the binaries (`rustc` >= 1.80).
- Tailscale installed and signed in. `tailscale status` should report your
  hostname, e.g. `kamils-macbook.tailXXXX.ts.net`.
- For external (non-tailnet) verifiers such as AWS STS: **Tailscale Funnel**
  enabled in the admin console under Settings -> Funnel and for the device.
  Without Funnel, only tailnet peers can fetch the JWKS.

## 1. Build and install

From the repo root:

```bash
cargo build --release
sudo ./packaging/install.sh
```

`install.sh` is idempotent. It:

1. Stops any existing instance via `launchctl bootout`.
2. Installs `/usr/local/sbin/keycard-osx-oidcd` (mode 0755) and
   `/usr/local/bin/keycard-osx-oidc` (mode 0755).
3. Creates `/etc/keycard-osx-oidcd/`, `/var/db/keycard-osx-oidcd/`, and
   `/var/db/keycard-osx-oidcd/keys/` (the state dirs are 0700).
4. Drops `packaging/config.example.toml` to `/etc/keycard-osx-oidcd/config.toml`
   *only if absent* -- existing configs are preserved across upgrades.
5. Touches `/var/log/keycard-osx-oidcd.log`.
6. Installs `/Library/LaunchDaemons/com.keycard.osx-oidcd.plist`.
7. If the config still has the placeholder issuer URL, **stops here** and
   prompts you to edit the file before loading the daemon. Otherwise it
   bootstraps + kickstarts the launchd job.

## 2. Configure `/etc/keycard-osx-oidcd/config.toml`

```toml
# Required: must match the URL Tailscale exposes (Step 4).
issuer = "https://kamils-macbook.tailXXXX.ts.net"

listen_http = "127.0.0.1:8080"
listen_uds  = "/var/run/keycard-osx-oidcd.sock"
keys_dir    = "/var/db/keycard-osx-oidcd/keys"

default_ttl_seconds = 3600
max_ttl_seconds     = 43200

# Empty list = "any audience allowed".
allowed_audiences = ["sts.amazonaws.com", "vault"]

rotation_interval_days   = 7
previous_key_grace_hours = 24
```

The daemon refuses to start if `issuer` is missing or not `https://`.

## 3. Load the launchd daemon

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.keycard.osx-oidcd.plist
sudo launchctl enable     system/com.keycard.osx-oidcd
sudo launchctl kickstart -kp system/com.keycard.osx-oidcd

sudo launchctl print system/com.keycard.osx-oidcd | grep '^[[:space:]]*state'
# state = running
```

First start generates `/var/db/keycard-osx-oidcd/keys/current.json` if absent.
The signing key persists across daemon restarts and across upgrades.

```bash
tail -f /var/log/keycard-osx-oidcd.log
curl -s http://127.0.0.1:8080/.well-known/openid-configuration | jq
curl -s http://127.0.0.1:8080/.well-known/jwks.json | jq
```

## 4. Expose discovery via Tailscale

For tailnet-only access:

```bash
sudo tailscale serve --bg --https=443 http://127.0.0.1:8080
sudo tailscale serve status
```

For public-internet access (required for AWS STS):

```bash
sudo tailscale serve  reset
sudo tailscale funnel --bg --https=443 http://127.0.0.1:8080
sudo tailscale funnel status
```

Note: older Tailscale docs/snippets show a `/` between the port and target URL
(`--https=443 / http://...`). The current `serve`/`funnel` CLI rejects that
form with "invalid usage" — the target is a single positional argument.

Verify externally:

```bash
curl -s https://kamils-macbook.tailXXXX.ts.net/.well-known/openid-configuration | jq
curl -s https://kamils-macbook.tailXXXX.ts.net/.well-known/jwks.json | jq
```

The `issuer` field in the response **must** equal the URL clients use.
If it doesn't, fix `/etc/keycard-osx-oidcd/config.toml` and restart with
`sudo launchctl kickstart -kp system/com.keycard.osx-oidcd`.

## 5. Verify end-to-end with a real token

As a regular (non-admin) user:

```bash
keycard-osx-oidc whoami
keycard-osx-oidc token --audience sts.amazonaws.com > /tmp/jwt.txt
cut -d. -f2 /tmp/jwt.txt | base64 -d 2>/dev/null | jq
```

Verify against the live JWKS (requires `jwt-cli`):

```bash
brew install jwt-cli   # one-time
jwt decode --jwks "https://kamils-macbook.tailXXXX.ts.net/.well-known/jwks.json" \
  "$(cat /tmp/jwt.txt)"
```

A second user account on the same Mac should get a token with a different
`uid`/`sub`. If both users mint a token and `sub` differs, identity binding
is working as designed.

## 6. Configure the external verifier

Pattern: point the verifier at the issuer URL; it will fetch JWKS itself.

### AWS STS / IAM (OIDC identity provider)

- Provider URL: `https://kamils-macbook.tailXXXX.ts.net`
- Audience(s): whatever you pass to `--audience`
- Trust policy match: `sub == "<machine_uuid>:<uid>"` or check
  `username` / `hostname` claims for human-readable policies.

### HashiCorp Vault JWT auth

```bash
vault write auth/jwt/config \
    oidc_discovery_url="https://kamils-macbook.tailXXXX.ts.net"
vault write auth/jwt/role/dev \
    role_type=jwt user_claim=username \
    bound_audiences=vault policies=dev
```

### Generic OIDC-aware app

Configure the app's "OIDC issuer URL" to the host URL; the app handles JWKS
discovery on its own.

## 7. Service management

| Operation | Command |
|---|---|
| Status | `sudo launchctl print system/com.keycard.osx-oidcd \| head` |
| Restart | `sudo launchctl kickstart -kp system/com.keycard.osx-oidcd` |
| Stop | `sudo launchctl bootout system/com.keycard.osx-oidcd` |
| Start | `sudo launchctl bootstrap system /Library/LaunchDaemons/com.keycard.osx-oidcd.plist` |
| Tail logs | `sudo tail -f /var/log/keycard-osx-oidcd.log` |
| View JWKS on disk | `sudo /usr/local/sbin/keycard-osx-oidcd dump-jwks` |
| Force key rotation | `sudo launchctl bootout system/com.keycard.osx-oidcd && sudo /usr/local/sbin/keycard-osx-oidcd rotate-keys && sudo launchctl bootstrap system /Library/LaunchDaemons/com.keycard.osx-oidcd.plist` |

## 8. Upgrade

```bash
git pull
cargo build --release
sudo ./packaging/install.sh
```

`install.sh` will stop the daemon, replace binaries, and restart. The signing
key in `/var/db/keycard-osx-oidcd/keys/` is preserved, so the issuer's JWKS
does not change and previously issued tokens still validate.

## 9. Uninstall

```bash
sudo ./packaging/uninstall.sh           # keep config + signing keys
sudo ./packaging/uninstall.sh --purge   # also remove config + keys + log
```

`uninstall.sh` performs:

```bash
launchctl bootout system/com.keycard.osx-oidcd
tailscale serve  reset
tailscale funnel reset
rm /Library/LaunchDaemons/com.keycard.osx-oidcd.plist
rm /usr/local/sbin/keycard-osx-oidcd
rm /usr/local/bin/keycard-osx-oidc
rm /var/run/keycard-osx-oidcd.sock
# --purge also removes /etc/keycard-osx-oidcd, /var/db/keycard-osx-oidcd, /var/log/keycard-osx-oidcd.log
```

`--purge` invalidates every previously-issued token (the signing key is gone).

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `launchctl print` reports `state = errored` | bad/missing `issuer` in config.toml | Edit config, then `sudo launchctl kickstart -kp system/com.keycard.osx-oidcd` |
| `keycard-osx-oidc token` -> `permission denied` | socket missing or wrong mode | `ls -l /var/run/keycard-osx-oidcd.sock` should be `srw-rw-rw-`. Restart the daemon. |
| External `curl` to discovery returns Tailscale 404 | `tailscale serve` rule missing | Re-run Step 4. `sudo tailscale serve status` should show port 443 -> 8080. |
| Verifier rejects `kid not found` | verifier cached JWKS from before rotation | Wait for the verifier's JWKS cache TTL, or force a refresh (e.g. `vault write -force auth/jwt/config oidc_discovery_url=...`). The previous key remains in JWKS for `previous_key_grace_hours` -- if you set that to 0, fresh tokens become unverifiable until caches refresh. |
| First launch blocked by Gatekeeper | binaries are not notarised | System Settings -> Privacy & Security -> "Allow anyway" for the daemon. After approval, `sudo launchctl kickstart -kp system/com.keycard.osx-oidcd`. |
