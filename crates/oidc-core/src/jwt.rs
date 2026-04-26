//! Minimal compact-JWS signer/verifier for `EdDSA` over Ed25519.
//!
//! We deliberately don't pull in a general-purpose JWT crate: the issuer
//! emits exactly one shape (header is always `{alg:"EdDSA", kid, typ:"JWT"}`)
//! and the verifier path is only used in tests.

use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};

use crate::b64;
use crate::claims::Claims;
use crate::error::{Error, Result};
use crate::jwk::Jwk;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

/// Sign `claims` with the supplied JWK. Returns the compact JWS form
/// `header.payload.signature`.
pub fn sign(jwk: &Jwk, claims: &Claims) -> Result<String> {
    let header = Header {
        alg: "EdDSA".to_string(),
        kid: jwk.kid(),
        typ: "JWT".to_string(),
    };
    let header_b64 = b64::encode(&serde_json::to_vec(&header)?);
    let payload_b64 = b64::encode(&serde_json::to_vec(claims)?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signing_key = jwk.signing_key()?;
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = b64::encode(&signature.to_bytes());

    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Verify a compact JWS and return the parsed claims if the signature is
/// valid against `jwk`. Does not check `exp`/`nbf`/`iss`/`aud` — that's the
/// verifier's job.
pub fn verify(jwk: &Jwk, token: &str) -> Result<Claims> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or(Error::InvalidJwt("missing header"))?;
    let payload_b64 = parts.next().ok_or(Error::InvalidJwt("missing payload"))?;
    let signature_b64 = parts.next().ok_or(Error::InvalidJwt("missing signature"))?;
    if parts.next().is_some() {
        return Err(Error::InvalidJwt("too many segments"));
    }

    let header_bytes = b64::decode(header_b64)?;
    let header: Header = serde_json::from_slice(&header_bytes)?;
    if header.alg != "EdDSA" {
        return Err(Error::InvalidJwt("unsupported alg"));
    }

    let signature_bytes = b64::decode(signature_b64)?;
    if signature_bytes.len() != 64 {
        return Err(Error::InvalidJwt("signature has wrong length"));
    }
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|_| Error::InvalidJwt("malformed signature"))?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    let verifying_key = jwk.verifying_key()?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| Error::BadSignature)?;

    let payload_bytes = b64::decode(payload_b64)?;
    let claims: Claims = serde_json::from_slice(&payload_bytes)?;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> Claims {
        Claims {
            iss: "https://host.tail.ts.net".into(),
            sub: "MID:501".into(),
            aud: "sts.amazonaws.com".into(),
            iat: 1_700_000_000,
            nbf: 1_700_000_000,
            exp: 1_700_003_600,
            uid: 501,
            username: "kamil".into(),
            hostname: "kamils-mac".into(),
            machine_id: "MID".into(),
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let jwk = Jwk::generate_ed25519();
        let token = sign(&jwk, &sample_claims()).unwrap();
        let claims = verify(&jwk.to_public(), &token).unwrap();
        assert_eq!(claims, sample_claims());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let jwk1 = Jwk::generate_ed25519();
        let jwk2 = Jwk::generate_ed25519();
        let token = sign(&jwk1, &sample_claims()).unwrap();
        let err = verify(&jwk2.to_public(), &token).unwrap_err();
        matches!(err, Error::BadSignature);
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let jwk = Jwk::generate_ed25519();
        let token = sign(&jwk, &sample_claims()).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_payload = b64::encode(b"{\"sub\":\"attacker\"}");
        parts[1] = &tampered_payload;
        let tampered = parts.join(".");
        let err = verify(&jwk.to_public(), &tampered).unwrap_err();
        matches!(err, Error::BadSignature);
    }

    #[test]
    fn header_advertises_kid_and_alg() {
        let jwk = Jwk::generate_ed25519();
        let token = sign(&jwk, &sample_claims()).unwrap();
        let header_b64 = token.split('.').next().unwrap();
        let header: Header = serde_json::from_slice(&b64::decode(header_b64).unwrap()).unwrap();
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, "JWT");
        assert_eq!(header.kid, jwk.kid());
    }
}
