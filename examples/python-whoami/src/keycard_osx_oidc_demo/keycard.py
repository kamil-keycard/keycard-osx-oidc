"""Talk to a Keycard zone using the official ``keycardai-oauth`` SDK.

The hard work -- RFC 8414 discovery, RFC 6749 client_credentials grant,
RFC 7523 JWT-bearer client assertion plumbing, error mapping -- already
lives in ``keycardai.oauth.Client``. This module only adds:

* Convenience constants for Keycard zone URLs.
* A small JWT decoder used for human-readable display of the local
  client-assertion JWT. The SDK does not expose a public JWT inspector
  and we never verify signatures here -- this is purely for the demo
  CLI to print what it is about to send as a client assertion.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from keycardai.oauth import Client, TokenResponse
from keycardai.oauth.types.models import (
    AuthorizationServerMetadata,
    TokenExchangeRequest,
)

DEFAULT_ZONE_ID = "o36mbsre94s2vlt8x5jq6nbxs0"

CLIENT_ASSERTION_TYPE_JWT_BEARER = (
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)


def zone_url(zone_id: str) -> str:
    return f"https://{zone_id}.keycard.cloud"


def default_resource(zone_id: str) -> str:
    return f"{zone_url(zone_id)}/events"


def discover_zone(zone_id: str) -> AuthorizationServerMetadata:
    """RFC 8414 metadata discovery against ``<zone_url>``.

    Just delegates to the SDK; surfaced here so the demo CLI can print the
    discovered ``token_endpoint`` (which is what the local JWT must list as
    its ``aud``) before doing the actual exchange.
    """
    with Client(zone_url(zone_id)) as client:
        return client.discover_server_metadata()


def request_resource_token(
    zone_id: str,
    *,
    client_assertion: str,
    resource: str,
) -> TokenResponse:
    """RFC 6749 §4.4 client_credentials grant, authenticated by an
    RFC 7523 JWT-bearer client assertion.

    The local OIDC daemon's JWT *is* the client identity; there is no
    separate subject token because the workload is acting on its own
    behalf. svc-sts attests the workload via the assertion's ``iss`` /
    ``sub`` claims (which it matches against a configured token
    application credential) and then issues an access token bound to
    ``resource`` (RFC 8707).
    """
    with Client(zone_url(zone_id)) as client:
        request = TokenExchangeRequest(
            grant_type="client_credentials",
            resource=resource,
            client_assertion=client_assertion,
            client_assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER,
        )
        return client.exchange_token(request)


def decode_jwt_unverified(jwt: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode a compact JWT for display only. No signature verification."""
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"not a compact JWT (expected 3 segments, got {len(parts)})"
        )
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)
