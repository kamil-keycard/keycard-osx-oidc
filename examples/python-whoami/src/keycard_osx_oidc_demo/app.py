"""Tiny demo CLI showing how a Python app can use the local OIDC daemon.

This is intentionally stdlib-only so it runs anywhere ``uv run keycard-demo``
can resolve a Python interpreter. It is **not** a production library;
treat it as a copy-paste reference for embedding ``KeycardClient`` into
your own service.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Sequence

from .client import (
    DEFAULT_REFRESH_SKEW_SECONDS,
    DEFAULT_SOCKET_PATH,
    CachedTokenProvider,
    KeycardClient,
    KeycardError,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keycard-demo",
        description=(
            "Example Python client for keycard-osx-oidcd. Demonstrates the "
            "Unix-socket protocol (Option 3 in the project README)."
        ),
    )
    parser.add_argument(
        "--socket",
        default=DEFAULT_SOCKET_PATH,
        help="Path to the daemon's Unix socket (default: %(default)s)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "whoami",
        help="Print the identity claims the daemon would mint a token for.",
    )

    p_token = sub.add_parser(
        "token",
        help="Mint a JWT for the given audience.",
    )
    p_token.add_argument("--audience", required=True)
    p_token.add_argument("--ttl-seconds", type=int, default=None)
    p_token.add_argument(
        "--show-claims",
        action="store_true",
        help="Print the decoded claims dict alongside the JWT.",
    )

    p_watch = sub.add_parser(
        "watch-cache",
        help=(
            "Long-running demo: maintain an in-process cached token and "
            "refresh it before expiry. Prints a status line on each refresh."
        ),
    )
    p_watch.add_argument("--audience", required=True)
    p_watch.add_argument("--ttl-seconds", type=int, default=None)
    p_watch.add_argument(
        "--refresh-skew-seconds",
        type=int,
        default=DEFAULT_REFRESH_SKEW_SECONDS,
    )
    p_watch.add_argument(
        "--max-iterations",
        type=int,
        default=0,
        help=(
            "Stop after N refresh cycles. 0 (default) means run until "
            "interrupted with Ctrl-C."
        ),
    )

    return parser


def cmd_whoami(client: KeycardClient) -> int:
    w = client.whoami()
    print(f"issuer:     {w.issuer}")
    print(f"sub:        {w.sub}")
    print(f"uid:        {w.uid}")
    print(f"username:   {w.username}")
    print(f"hostname:   {w.hostname}")
    print(f"machine_id: {w.machine_id}")
    return 0


def cmd_token(
    client: KeycardClient,
    *,
    audience: str,
    ttl_seconds: int | None,
    show_claims: bool,
) -> int:
    t = client.get_token(audience, ttl_seconds=ttl_seconds)
    print(t.token)
    if show_claims:
        print(json.dumps(t.claims, indent=2, sort_keys=True), file=sys.stderr)
        print(
            f"# expires_at={t.expires_at} ({t.seconds_remaining()}s remaining)",
            file=sys.stderr,
        )
    return 0


def cmd_watch_cache(
    client: KeycardClient,
    *,
    audience: str,
    ttl_seconds: int | None,
    refresh_skew_seconds: int,
    max_iterations: int,
) -> int:
    provider = CachedTokenProvider(
        client,
        audience,
        ttl_seconds=ttl_seconds,
        refresh_skew_seconds=refresh_skew_seconds,
    )
    iterations = 0
    try:
        while True:
            token = provider.get()
            remaining = token.seconds_remaining()
            print(
                f"[{time.strftime('%H:%M:%S')}] "
                f"kid={token.claims.get('kid', '?')} "
                f"sub={token.claims.get('sub', '?')} "
                f"exp_in={remaining}s",
                flush=True,
            )
            iterations += 1
            if max_iterations and iterations >= max_iterations:
                return 0
            sleep_for = max(15, remaining - refresh_skew_seconds)
            time.sleep(sleep_for)
            provider.invalidate()
    except KeyboardInterrupt:
        return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    client = KeycardClient(socket_path=args.socket)

    try:
        if args.command == "whoami":
            return cmd_whoami(client)
        if args.command == "token":
            return cmd_token(
                client,
                audience=args.audience,
                ttl_seconds=args.ttl_seconds,
                show_claims=args.show_claims,
            )
        if args.command == "watch-cache":
            return cmd_watch_cache(
                client,
                audience=args.audience,
                ttl_seconds=args.ttl_seconds,
                refresh_skew_seconds=args.refresh_skew_seconds,
                max_iterations=args.max_iterations,
            )
    except KeycardError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
