"""Stdlib-only client for the keycard-osx-oidcd Unix-socket protocol.

The daemon exchanges newline-delimited JSON over
``/var/run/keycard-osx-oidcd.sock``: one request line in, one response line
out, then close. The daemon binds the resulting JWT to the connecting
process's UID via ``getpeereid()`` -- the request body cannot influence
identity. See ``crates/oidc-core/src/protocol.rs`` for the wire format.
"""

from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Any

DEFAULT_SOCKET_PATH = "/var/run/keycard-osx-oidcd.sock"
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_REFRESH_SKEW_SECONDS = 300


class KeycardError(RuntimeError):
    """Raised when the daemon returns an error or the protocol is violated."""


@dataclass(frozen=True)
class WhoamiResponse:
    sub: str
    uid: int
    username: str
    hostname: str
    machine_id: str
    issuer: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "WhoamiResponse":
        return cls(
            sub=payload["sub"],
            uid=int(payload["uid"]),
            username=payload["username"],
            hostname=payload["hostname"],
            machine_id=payload["machine_id"],
            issuer=payload["issuer"],
        )


@dataclass(frozen=True)
class TokenResponse:
    token: str
    expires_at: int
    claims: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TokenResponse":
        return cls(
            token=payload["token"],
            expires_at=int(payload["expires_at"]),
            claims=dict(payload.get("claims", {})),
        )

    def seconds_remaining(self, now: int | None = None) -> int:
        return max(0, self.expires_at - (now if now is not None else int(time.time())))

    def needs_refresh(self, skew_seconds: int = DEFAULT_REFRESH_SKEW_SECONDS) -> bool:
        return self.seconds_remaining() <= skew_seconds


class KeycardClient:
    """Minimal client for the local keycard-osx-oidcd daemon.

    The client is intentionally synchronous and dependency-free; one round
    trip per call. For long-running services prefer the file-mapped pattern
    (see the project README) and use a watcher process to keep the file
    fresh.
    """

    def __init__(
        self,
        socket_path: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.socket_path = socket_path or os.environ.get(
            "KEYCARD_OSX_OIDC_SOCKET", DEFAULT_SOCKET_PATH
        )
        self.timeout = timeout

    def whoami(self) -> WhoamiResponse:
        payload = self._round_trip({"op": "whoami"})
        return WhoamiResponse.from_dict(payload)

    def get_token(
        self,
        audience: str,
        ttl_seconds: int | None = None,
    ) -> TokenResponse:
        request: dict[str, Any] = {"op": "token", "audience": audience}
        if ttl_seconds is not None:
            request["ttl_seconds"] = int(ttl_seconds)
        payload = self._round_trip(request)
        return TokenResponse.from_dict(payload)

    def _round_trip(self, request: dict[str, Any]) -> dict[str, Any]:
        line = (json.dumps(request) + "\n").encode("utf-8")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            try:
                s.connect(self.socket_path)
            except FileNotFoundError as err:
                raise KeycardError(
                    f"daemon socket not found at {self.socket_path}; "
                    "is keycard-osx-oidcd running?"
                ) from err
            except PermissionError as err:
                raise KeycardError(
                    f"permission denied connecting to {self.socket_path}"
                ) from err
            s.sendall(line)
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            buf = bytearray()
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
        if not buf:
            raise KeycardError("daemon closed connection without a response")
        first_line = buf.split(b"\n", 1)[0]
        try:
            payload = json.loads(first_line.decode("utf-8"))
        except json.JSONDecodeError as err:
            raise KeycardError(
                f"could not parse daemon response: {first_line!r}"
            ) from err
        if isinstance(payload, dict) and "error" in payload and len(payload) == 1:
            raise KeycardError(f"daemon error: {payload['error']}")
        if not isinstance(payload, dict):
            raise KeycardError(f"unexpected daemon response: {payload!r}")
        return payload


class CachedTokenProvider:
    """Convenience wrapper that caches a JWT in-process and refreshes on expiry.

    Suitable for short-lived processes and one-shot scripts. Long-running
    services should prefer the file-mapped pattern (the daemon's CLI watcher
    writes a 0600 file that an unrelated process can read).
    """

    def __init__(
        self,
        client: KeycardClient,
        audience: str,
        *,
        ttl_seconds: int | None = None,
        refresh_skew_seconds: int = DEFAULT_REFRESH_SKEW_SECONDS,
    ) -> None:
        self._client = client
        self._audience = audience
        self._ttl_seconds = ttl_seconds
        self._refresh_skew_seconds = refresh_skew_seconds
        self._cached: TokenResponse | None = None

    def get(self) -> TokenResponse:
        if self._cached is None or self._cached.needs_refresh(
            self._refresh_skew_seconds
        ):
            self._cached = self._client.get_token(
                self._audience, ttl_seconds=self._ttl_seconds
            )
        return self._cached

    def invalidate(self) -> None:
        self._cached = None
