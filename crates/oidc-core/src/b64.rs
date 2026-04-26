//! Base64url helpers used by JWS, JWK, and JWT serialisation.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}
