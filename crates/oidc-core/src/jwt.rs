//! Minimal compact-JWS signer/verifier for `RS256` (RSASSA-PKCS1-v1_5 + SHA-256).
//!
//! We deliberately don't pull in a general-purpose JWT crate: the issuer
//! emits exactly one shape (header is always `{alg:"RS256", kid, typ:"JWT"}`)
//! and the verifier path is only used in tests.

use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
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
        alg: "RS256".to_string(),
        kid: jwk.kid(),
        typ: "JWT".to_string(),
    };
    let header_b64 = b64::encode(&serde_json::to_vec(&header)?);
    let payload_b64 = b64::encode(&serde_json::to_vec(claims)?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signing_key: SigningKey<Sha256> = SigningKey::new(jwk.signing_key()?);
    let signature = signing_key
        .try_sign(signing_input.as_bytes())
        .map_err(|_| Error::InvalidJwt("signing failed"))?;
    let signature_b64 = b64::encode(&signature.to_bytes());

    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Verify a compact JWS and return the parsed claims if the signature is
/// valid against `jwk`. Does not check `exp`/`nbf`/`iss`/`aud` -- that's the
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
    if header.alg != "RS256" {
        return Err(Error::InvalidJwt("unsupported alg"));
    }

    let signature_bytes = b64::decode(signature_b64)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| Error::InvalidJwt("malformed signature"))?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(jwk.verifying_key()?);
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
            agent_id: None,
        }
    }

    fn sample_claims_with_agent() -> Claims {
        Claims {
            agent_id: Some("agent-42".into()),
            ..sample_claims()
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let jwk = Jwk::generate_rsa(2048);
        let token = sign(&jwk, &sample_claims()).unwrap();
        let claims = verify(&jwk.to_public(), &token).unwrap();
        assert_eq!(claims, sample_claims());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let jwk1 = Jwk::generate_rsa(2048);
        let jwk2 = Jwk::generate_rsa(2048);
        let token = sign(&jwk1, &sample_claims()).unwrap();
        let err = verify(&jwk2.to_public(), &token).unwrap_err();
        matches!(err, Error::BadSignature);
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let jwk = Jwk::generate_rsa(2048);
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
        let jwk = Jwk::generate_rsa(2048);
        let token = sign(&jwk, &sample_claims()).unwrap();
        let header_b64 = token.split('.').next().unwrap();
        let header: Header = serde_json::from_slice(&b64::decode(header_b64).unwrap()).unwrap();
        assert_eq!(header.alg, "RS256");
        assert_eq!(header.typ, "JWT");
        assert_eq!(header.kid, jwk.kid());
    }

    #[test]
    fn agent_id_roundtrips_when_set() {
        let jwk = Jwk::generate_rsa(2048);
        let claims = sample_claims_with_agent();
        let token = sign(&jwk, &claims).unwrap();
        let decoded = verify(&jwk.to_public(), &token).unwrap();
        assert_eq!(decoded.agent_id, Some("agent-42".to_string()));
        assert_eq!(decoded, claims);
    }

    #[test]
    fn agent_id_absent_from_payload_when_unset() {
        let jwk = Jwk::generate_rsa(2048);
        let token = sign(&jwk, &sample_claims()).unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&b64::decode(payload_b64).unwrap()).unwrap();
        assert!(
            payload.get("agent_id").is_none(),
            "agent_id should be skipped when None: {payload:?}"
        );
    }
}
