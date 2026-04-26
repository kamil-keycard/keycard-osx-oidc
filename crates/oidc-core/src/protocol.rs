//! Wire format for the local Unix-socket protocol.
//!
//! The daemon and the CLI exchange newline-delimited JSON over
//! `/var/run/keycard-osx-oidcd.sock`. One request line, one response line,
//! then close.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Token {
        audience: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl_seconds: Option<u64>,
    },
    Whoami,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Token(TokenResponse),
    Whoami(WhoamiResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_at: i64,
    pub claims: crate::Claims,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiResponse {
    pub sub: String,
    pub uid: u32,
    pub username: String,
    pub hostname: String,
    pub machine_id: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
