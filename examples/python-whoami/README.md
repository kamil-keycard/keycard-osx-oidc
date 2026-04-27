# keycard-osx-oidc-demo

Example Python application that talks directly to the local
`keycard-osx-oidcd` daemon over its Unix socket and obtains its own
identity JWT. Implements **Option 3** from the project [README](../../README.md#python-integration):
the network stack is never involved.

```
your Python app
   │
   │  AF_UNIX  (newline-delimited JSON, one round trip)
   ▼
/var/run/keycard-osx-oidcd.sock
   │  daemon calls getpeereid() on the accepted fd → kernel-asserted UID
   ▼
keycard-osx-oidcd  → signs JWT with the current Ed25519 key → returns it
```

The daemon binds the resulting JWT to the connecting process's UID; the
request body cannot influence identity. There is no token endpoint on
the HTTP listener, and the UDS is filesystem-only — remote callers cannot
reach this code path.

## Layout

```
examples/python-whoami/
├── pyproject.toml
└── src/keycard_osx_oidc_demo/
    ├── __init__.py
    ├── client.py   # KeycardClient, TokenResponse, CachedTokenProvider
    └── app.py      # demo CLI: whoami / token / watch-cache
```

`client.py` is stdlib-only and copy-paste ready — depend on nothing,
embed it in your own service. `app.py` is the user-facing demo.

## Run it

The daemon must be running and your user must be able to connect to
`/var/run/keycard-osx-oidcd.sock` (the daemon ships it as `0666` so any
local user can — identity is asserted by the kernel, not by socket
permissions).

```bash
cd examples/python-whoami

# uv resolves the interpreter, builds an editable install, and runs the
# entry point declared in [project.scripts].
uv run keycard-demo whoami

uv run keycard-demo token --audience sts.amazonaws.com
uv run keycard-demo token --audience sts.amazonaws.com --show-claims

# Long-running demo: keep an in-process token fresh until Ctrl-C.
uv run keycard-demo watch-cache --audience sts.amazonaws.com
```

If the daemon isn't running you'll see:

```
error: daemon socket not found at /var/run/keycard-osx-oidcd.sock; is keycard-osx-oidcd running?
```

## Embedding `KeycardClient` in your own app

```python
from keycard_osx_oidc_demo import KeycardClient, CachedTokenProvider

client = KeycardClient()  # defaults to /var/run/keycard-osx-oidcd.sock

identity = client.whoami()
print(identity.username, identity.sub)

# One-shot
tok = client.get_token("sts.amazonaws.com")
print(tok.token, tok.expires_at)

# In-process cache with proactive refresh
provider = CachedTokenProvider(client, "sts.amazonaws.com",
                               refresh_skew_seconds=300)
jwt = provider.get().token   # mints on first call
jwt = provider.get().token   # returns cached value until 5min before exp
```

Use this pattern for short scripts and request-scoped caches. For
long-running services that should not embed the client at all — e.g. an
existing process that already speaks the EKS workload-identity protocol —
prefer the file-mapped pattern (Option 1 in the project README): run
`keycard-osx-oidc token --watch --output …` as a sidecar/LaunchAgent and
point the consumer at the file.

## Wire format reference

The protocol is one line of JSON in, one line of JSON out, then close.
Defined in `crates/oidc-core/src/protocol.rs`:

```json
// Request
{"op": "whoami"}
{"op": "token", "audience": "sts.amazonaws.com", "ttl_seconds": 3600}

// Response
{"sub": "...", "uid": 501, "username": "...", "hostname": "...",
 "machine_id": "...", "issuer": "..."}
{"token": "<jwt>", "expires_at": 1700003600, "claims": { ... }}
{"error": "human-readable reason"}
```

Error responses are exactly `{"error": "..."}`; anything else with that
shape is a real claim payload. `KeycardClient._round_trip` discriminates
on that.
