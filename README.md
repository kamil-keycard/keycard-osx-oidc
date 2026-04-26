# keycard-osx-oidc

A local OIDC issuer for macOS. Each user on the host can mint a signed JWT
representing their identity; external services (AWS STS, Vault, custom apps)
trust those tokens by fetching the issuer's JWKS over the network. The model
mirrors EKS IRSA: token issuance is internal/local, discovery + JWKS are
public.

```
+----------------------------------------------------+
|                  macOS host                        |
|                                                    |
|  user proc  --(UDS)-->  keycard-osx-oidcd  --+     |
|  (uid=501)              (launchd, root)      |     |
|                                              |     |
|                          /var/db/.../keys/   |     |
|                                              v     |
|                          127.0.0.1:8080  ---tailscale serve--+
+----------------------------------------------------+         |
                                                               v
                       External verifier (STS/Vault/app)  GET /.well-known/jwks.json
```

## Components

- **`keycard-osx-oidcd`** — privileged daemon, loaded by launchd as `root`.
  Listens on a Unix socket for token requests (UID-bound via `getpeereid`)
  and on `127.0.0.1:8080` for discovery + JWKS.
- **`keycard-osx-oidc`** — unprivileged user CLI. `keycard-osx-oidc token
  --audience <aud>` returns a signed JWT.

## Token shape

```json
{
  "iss": "https://<host>.<tailnet>.ts.net",
  "sub": "<machine_uuid>:<uid>",
  "aud": "sts.amazonaws.com",
  "iat": 1700000000,
  "nbf": 1700000000,
  "exp": 1700003600,
  "uid": 501,
  "username": "kamil",
  "hostname": "kamils-macbook",
  "machine_id": "C0FFEE-..."
}
```

Signed with Ed25519 (`alg=EdDSA`). The `kid` in the header is the RFC 7638
JWK thumbprint of the signing key. Keys rotate every 7 days; the previous
key stays in JWKS for a 24h grace window.

## Quickstart (macOS)

```bash
# Build, install, and load the daemon
cargo build --release
sudo ./packaging/install.sh

# Edit issuer URL to match your Tailscale hostname
sudo vi /etc/keycard-osx-oidcd/config.toml
sudo launchctl kickstart -kp system/com.keycard.osx-oidcd

# Expose discovery via Tailscale
sudo tailscale serve --bg --https=443 http://127.0.0.1:8080

# Mint a token as a regular user
keycard-osx-oidc whoami
keycard-osx-oidc token --audience sts.amazonaws.com
```

See [ADMIN.md](ADMIN.md) for the full deployment, verification, upgrade, and
uninstall runbook.

## Layout

| Path | Purpose |
|------|---------|
| `crates/oidc-core/` | JWK/JWKS, JWT sign/verify, claims, discovery doc |
| `crates/oidcd/` | The `keycard-osx-oidcd` daemon binary |
| `crates/cli/` | The `keycard-osx-oidc` user CLI binary |
| `packaging/` | LaunchDaemon plist, install/uninstall scripts, example config |

## License

MIT. See [LICENSE](LICENSE).
