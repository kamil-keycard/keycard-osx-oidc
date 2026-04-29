//! Claims emitted by `keycard-osx-oidcd`.
//!
//! `sub` is `<machine_id>:<uid>` and is opaque/stable. Username and hostname
//! are surfaced as separate claims so verifier policies can match either.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub uid: u32,
    pub username: String,
    pub hostname: String,
    pub machine_id: String,
    /// Optional caller-asserted agent identifier. v1: not authenticated;
    /// any local process talking to the daemon may set this. Verifier policy
    /// keying on `(sub, agent_id)` is the source of truth for per-agent scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}
