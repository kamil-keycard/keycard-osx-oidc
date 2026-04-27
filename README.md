# keycard-osx-oidc

A local OIDC issuer for macOS. Each user on the host can mint a signed JWT
representing their identity; external services (AWS STS, Vault, custom apps)
trust those tokens by fetching the issuer's JWKS over the network. The model
mirrors EKS IRSA: **token issuance is internal/local, discovery + JWKS are
public**.

## Components

- **`keycard-osx-oidcd`** — privileged daemon, loaded by launchd as `root`.
  Listens on a Unix socket for token requests (UID-bound via `getpeereid`)
  and on `127.0.0.1:8080` for discovery + JWKS.
- **`keycard-osx-oidc`** — unprivileged user CLI. `keycard-osx-oidc token
  --audience <aud>` returns a signed JWT.

## Network exposure

```mermaid
flowchart LR
    subgraph host["macOS host"]
        direction TB
        user["user process<br/>(uid=501)"]
        cli["keycard-osx-oidc<br/>(CLI)"]
        uds[("/var/run/keycard-osx-oidcd.sock<br/>UDS · mode 0666 · getpeereid binds uid")]
        daemon["keycard-osx-oidcd<br/>(launchd, root)"]
        keys[("/var/db/keycard-osx-oidcd/keys/<br/>signing key (0600)")]
        http["127.0.0.1:8080<br/>discovery + JWKS only<br/>(no token route)"]
        ts["tailscaled<br/>(reads loopback, terminates TLS)"]

        user --> cli --> uds --> daemon
        daemon --> keys
        daemon --> http
        http -. loopback only .-> ts
    end

    extProv["External verifier<br/>(AWS STS / Vault / app)"]

    ts ==>|"https://&lt;host&gt;.&lt;tailnet&gt;.ts.net<br/>only /.well-known/* exposed"| extProv

    classDef secret fill:#fee,stroke:#a00,color:#000;
    classDef public fill:#efe,stroke:#080,color:#000;
    class uds,keys secret
    class extProv,ts public
```

| Endpoint | Bound to | Reachable from | Carries token? |
|---|---|---|---|
| `/var/run/keycard-osx-oidcd.sock` | filesystem (UDS) | only processes on this Mac | yes — mints JWTs |
| `127.0.0.1:8080/.well-known/openid-configuration` | loopback TCP | only this Mac (incl. `tailscaled`) | no |
| `127.0.0.1:8080/.well-known/jwks.json` | loopback TCP | only this Mac (incl. `tailscaled`) | no — public key only |
| `127.0.0.1:8080/healthz` | loopback TCP | only this Mac | no |
| `https://<host>.<tailnet>.ts.net/.well-known/*` | `tailscaled` (`serve`/`funnel`) | tailnet peers (`serve`) or public Internet (`funnel`) | no — public key only |

## Security boundary: why remote callers cannot mint tokens

Three independent guarantees, any one of which is sufficient:

1. **No token route on the HTTP server.** The discovery server registers
   exactly three handlers: `/.well-known/openid-configuration`,
   `/.well-known/jwks.json`, `/healthz`. There is no `/token`,
   `/oauth/token`, or equivalent. Tailscale can only proxy what the HTTP
   listener exposes, and the HTTP listener exposes no way to mint a token.
   See `crates/oidcd/src/discovery.rs::router`.
2. **Token issuance lives on a Unix socket.** `/var/run/keycard-osx-oidcd.sock`
   is a filesystem object, not a network endpoint. Tailscale `serve`/`funnel`
   only proxies TCP listeners; it has no way to forward to a UDS. The
   network stack literally cannot reach this socket.
3. **Identity is asserted by the kernel.** When a process connects to the
   UDS the daemon calls `getpeereid()` on the accepted fd — the kernel
   reports the connecting process's UID, the client cannot influence it.
   The minted JWT's `sub`/`uid`/`username` claims are derived from that
   kernel-asserted UID, not from anything in the request body.

Defence in depth:

- The HTTP listener defaults to `127.0.0.1:8080`. The daemon emits a
  `WARN` log on startup if `listen_http` is configured to bind to a
  non-loopback address (see `is_loopback_listen` in `crates/oidcd/src/main.rs`).
- The signing key file (`/var/db/keycard-osx-oidcd/keys/current.json`) is
  mode `0600` owned by `root`. Only the daemon can read it; the public
  side is published in JWKS without `d`.

The intended threat model: any process on the Mac can request a token, but
the token it gets back is bound to that process's own UID — it cannot
impersonate another user. Off-host callers can only fetch the public JWKS,
which is exactly what verifiers need to validate tokens but cannot use to
mint new ones.

## Python integration

There are two practical patterns for getting a token into a Python process.
Pick based on lifetime and how much you control the consumer.

### Option 1: file-mapped token (recommended for long-running services)

Run the CLI's watch loop as a per-user `LaunchAgent` (or any supervisor).
It writes the raw JWT — atomically, mode `0600`, no trailing newline — to
a file you control and re-mints it before expiry:

```bash
keycard-osx-oidc token \
  --audience sts.amazonaws.com \
  --output "$HOME/.keycard/token" \
  --watch \
  --refresh-skew-seconds 300
```

The consumer just reads the file. This is intentionally compatible with
the EKS IRSA pattern, so an existing `EKSWorkloadIdentity`-style provider
works unchanged:

```python
from keycardai.oauth.server.credentials import EKSWorkloadIdentity

provider = EKSWorkloadIdentity(
    token_file_path=f"{os.environ['HOME']}/.keycard/token",
)
```

A LaunchAgent template lives at `packaging/launchd/keycard-osx-oidc-token.plist.example`
(forthcoming). The advantage: the consumer never knows about UDS, never
forks, and crash-loops on the watcher don't take the consumer down — it
keeps reading the last-known-good token until expiry.

### Option 2: shell out to the CLI

```python
import subprocess

def get_token(audience: str) -> str:
    return subprocess.check_output(
        ["keycard-osx-oidc", "token", "--audience", audience],
        text=True,
    ).strip()
```

Cheap (one UDS round trip) but you'll want to cache the result and
refresh on `exp` to avoid forking on every API call.

### Option 3: speak the UDS protocol directly

A working example lives at [`examples/python-whoami/`](examples/python-whoami/).
The UDS half is stdlib-only; the Keycard half delegates to the official
[`keycardai-oauth`](https://pypi.org/project/keycardai-oauth/) SDK so we
don't reimplement RFC 8414 / 8693 / 7523. Includes a `whoami`, `token`,
`watch-cache`, and `exchange` demo CLI:

```bash
cd examples/python-whoami
uv run keycard-demo whoami
uv run keycard-demo token --audience sts.amazonaws.com
uv run keycard-demo watch-cache --audience sts.amazonaws.com

# RFC 8693 token exchange against a Keycard zone
uv run keycard-demo exchange --zone-id <zone-id>
```

Embedding it in your own app:

```python
from keycard_osx_oidc_demo import KeycardClient, discover_zone, exchange

local = KeycardClient()
metadata = discover_zone("o36mbsre94s2vlt8x5jq6nbxs0")
subject = local.get_token(audience=metadata.token_endpoint)
response = exchange(
    "o36mbsre94s2vlt8x5jq6nbxs0",
    subject_token=subject.token,
    resource="https://o36mbsre94s2vlt8x5jq6nbxs0.keycard.cloud/events",
)
print(response.access_token)  # keycardai.oauth.TokenResponse
```

Use this when you need claims/`expires_at` in-process and don't want
either a sidecar (Option 1) or a subprocess fork (Option 2). The daemon
binds identity via `getpeereid()` on the accepted fd, so the JWT you get
back is bound to your process's UID regardless of which path you used.

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
| `examples/python-whoami/` | Python `uv` example using the UDS protocol directly |

## License

MIT. See [LICENSE](LICENSE).
