//! JWK / JWKS types for Ed25519 (RFC 8037 OKP / Ed25519).
//!
//! A `Jwk` carries either a public key only or a public+private key pair.
//! The serialised form follows RFC 7517 with the OKP additions from RFC 8037.

use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::b64;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    /// Public key, base64url no-pad.
    pub x: String,
    /// Private key, base64url no-pad. Only present on the daemon's signing key
    /// (the one stored under `/var/db/keycard-osx-oidcd/keys/`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "use")]
    pub use_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwk {
    /// Generate a fresh Ed25519 signing JWK, populating `kid` from the
    /// RFC 7638 thumbprint and tagging `use=sig`, `alg=EdDSA`.
    pub fn generate_ed25519() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(&signing)
    }

    pub fn from_signing_key(signing: &SigningKey) -> Self {
        let verifying = signing.verifying_key();
        let mut jwk = Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: b64::encode(verifying.as_bytes()),
            d: Some(b64::encode(&signing.to_bytes())),
            kid: None,
            use_: Some("sig".to_string()),
            alg: Some("EdDSA".to_string()),
        };
        jwk.kid = Some(jwk.thumbprint());
        jwk
    }

    /// Strip the private component, returning a JWK suitable for publishing
    /// in a JWKS response.
    pub fn to_public(&self) -> Jwk {
        Jwk {
            d: None,
            ..self.clone()
        }
    }

    /// RFC 7638 JWK Thumbprint: SHA-256 over the canonical JSON of the
    /// required members in lexicographic order. For OKP/Ed25519 the required
    /// members are `crv`, `kty`, `x`.
    pub fn thumbprint(&self) -> String {
        let canonical = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#,
            self.crv, self.kty, self.x
        );
        let digest = Sha256::digest(canonical.as_bytes());
        b64::encode(&digest)
    }

    pub fn signing_key(&self) -> Result<SigningKey> {
        let d = self.d.as_deref().ok_or(Error::InvalidJwk("missing d"))?;
        let bytes = b64::decode(d)?;
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(Error::InvalidJwk("d has wrong length"));
        }
        let mut buf = [0u8; SECRET_KEY_LENGTH];
        buf.copy_from_slice(&bytes);
        Ok(SigningKey::from_bytes(&buf))
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let bytes = b64::decode(&self.x)?;
        if bytes.len() != 32 {
            return Err(Error::InvalidJwk("x has wrong length"));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&buf).map_err(Error::from)
    }

    pub fn kid(&self) -> String {
        self.kid.clone().unwrap_or_else(|| self.thumbprint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_has_thumbprint_kid() {
        let jwk = Jwk::generate_ed25519();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.alg.as_deref(), Some("EdDSA"));
        assert_eq!(jwk.use_.as_deref(), Some("sig"));
        assert!(jwk.d.is_some());
        assert_eq!(jwk.kid.as_deref().unwrap(), jwk.thumbprint());
    }

    #[test]
    fn to_public_strips_private_component() {
        let jwk = Jwk::generate_ed25519();
        let pub_jwk = jwk.to_public();
        assert!(pub_jwk.d.is_none());
        assert_eq!(pub_jwk.x, jwk.x);
        assert_eq!(pub_jwk.kid, jwk.kid);
    }

    #[test]
    fn signing_and_verifying_keys_roundtrip() {
        let jwk = Jwk::generate_ed25519();
        let sk = jwk.signing_key().unwrap();
        let vk = jwk.verifying_key().unwrap();
        assert_eq!(sk.verifying_key().as_bytes(), vk.as_bytes());
    }

    #[test]
    fn thumbprint_is_stable_for_same_x() {
        let jwk = Jwk::generate_ed25519();
        let public = jwk.to_public();
        assert_eq!(jwk.thumbprint(), public.thumbprint());
    }
}
