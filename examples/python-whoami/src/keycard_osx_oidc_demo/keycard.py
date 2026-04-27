"""Talk to a Keycard zone using the official ``keycardai-oauth`` SDK.

The hard work -- RFC 8414 discovery, RFC 8693 token exchange, RFC 7523
JWT-bearer client assertion plumbing, error mapping -- already lives in
``keycardai.oauth.Client``. This module only adds:

* Convenience constants for Keycard zone URLs.
* A small JWT decoder used for human-readable display of the local subject
  token. The SDK does not expose a public JWT inspector and we never
  verify signatures here -- this is purely for the demo CLI to print
  what it is about to exchange.
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

SUBJECT_TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
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


def exchange(
    zone_id: str,
    *,
    subject_token: str,
    resource: str,
    use_client_assertion: bool = True,
) -> TokenResponse:
    """RFC 8693 token exchange via the SDK.

    The same JWT is presented as both the subject token and (by default) a
    JWT-bearer client assertion (RFC 7523). This is the workload-identity
    pattern: one JWT proves the calling identity *and* that the calling
    workload is a registered client. Disable client assertion if the zone
    treats the IdP as a public client.
    """
    with Client(zone_url(zone_id)) as client:
        request = TokenExchangeRequest(
            subject_token=subject_token,
            subject_token_type=SUBJECT_TOKEN_TYPE_JWT,
            resource=resource,
        )
        if use_client_assertion:
            request.client_assertion = subject_token
            request.client_assertion_type = CLIENT_ASSERTION_TYPE_JWT_BEARER
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
