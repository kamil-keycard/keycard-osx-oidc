//! JWK / JWKS types for RSA (RFC 7517 / RFC 7518 §6.3).
//!
//! A `Jwk` carries either a public key only or a public+private key pair.
//! Private JWKs include the full set of CRT parameters (`d`, `p`, `q`, `dp`,
//! `dq`, `qi`) so they can be reloaded without re-running prime recovery.

use rand::rngs::OsRng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::b64;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    /// Modulus, base64url no-pad.
    pub n: String,
    /// Public exponent, base64url no-pad.
    pub e: String,
    /// Private exponent. Only present on the daemon's signing key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub d: Option<String>,
    /// First prime factor.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub p: Option<String>,
    /// Second prime factor.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub q: Option<String>,
    /// First factor CRT exponent: `d mod (p - 1)`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dp: Option<String>,
    /// Second factor CRT exponent: `d mod (q - 1)`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dq: Option<String>,
    /// First CRT coefficient: `q^-1 mod p`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub qi: Option<String>,
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
    /// Generate a fresh RSA signing JWK at the requested modulus size, with
    /// `kid` set to the RFC 7638 thumbprint and tagged `use=sig`, `alg=RS256`.
    pub fn generate_rsa(bits: usize) -> Self {
        let mut signing = RsaPrivateKey::new(&mut OsRng, bits)
            .expect("RSA key generation should succeed for valid bit sizes");
        // `from_components` already calls precompute, but `new` does not in
        // every release; calling it here is idempotent.
        let _ = signing.precompute();
        Self::from_signing_key(&signing)
    }

    pub fn from_signing_key(signing: &RsaPrivateKey) -> Self {
        let n = b64::encode(&signing.n().to_bytes_be());
        let e = b64::encode(&signing.e().to_bytes_be());
        let d = b64::encode(&PrivateKeyParts::d(signing).to_bytes_be());
        let primes = PrivateKeyParts::primes(signing);
        let p = b64::encode(&primes[0].to_bytes_be());
        let q = b64::encode(&primes[1].to_bytes_be());
        let dp = PrivateKeyParts::dp(signing).map(|v| b64::encode(&v.to_bytes_be()));
        let dq = PrivateKeyParts::dq(signing).map(|v| b64::encode(&v.to_bytes_be()));
        // qinv is a `BigInt`; the JWK form is the magnitude, base64url no-pad.
        let qi = PrivateKeyParts::qinv(signing).map(|v| b64::encode(&v.to_bytes_be().1));

        let mut jwk = Jwk {
            kty: "RSA".to_string(),
            n,
            e,
            d: Some(d),
            p: Some(p),
            q: Some(q),
            dp,
            dq,
            qi,
            kid: None,
            use_: Some("sig".to_string()),
            alg: Some("RS256".to_string()),
        };
        jwk.kid = Some(jwk.thumbprint());
        jwk
    }

    /// Strip private components, returning a JWK suitable for publishing
    /// in a JWKS response.
    pub fn to_public(&self) -> Jwk {
        Jwk {
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            ..self.clone()
        }
    }

    /// RFC 7638 JWK Thumbprint: SHA-256 over the canonical JSON of the
    /// required members in lexicographic order. For RSA the required
    /// members are `e`, `kty`, `n`.
    pub fn thumbprint(&self) -> String {
        let canonical = format!(
            r#"{{"e":"{}","kty":"{}","n":"{}"}}"#,
            self.e, self.kty, self.n
        );
        let digest = Sha256::digest(canonical.as_bytes());
        b64::encode(&digest)
    }

    pub fn signing_key(&self) -> Result<RsaPrivateKey> {
        let n = decode_uint(&self.n, "n")?;
        let e = decode_uint(&self.e, "e")?;
        let d_str = self.d.as_deref().ok_or(Error::InvalidJwk("missing d"))?;
        let d = decode_uint(d_str, "d")?;

        // Prefer the full prime set when supplied so we skip the
        // prime-recovery path. Both RFC 7518 §6.3.2 and our own
        // `from_signing_key` always emit `p` and `q` together.
        let primes = match (self.p.as_deref(), self.q.as_deref()) {
            (Some(p), Some(q)) => vec![decode_uint(p, "p")?, decode_uint(q, "q")?],
            _ => Vec::new(),
        };

        RsaPrivateKey::from_components(n, e, d, primes).map_err(Error::from)
    }

    pub fn verifying_key(&self) -> Result<RsaPublicKey> {
        let n = decode_uint(&self.n, "n")?;
        let e = decode_uint(&self.e, "e")?;
        RsaPublicKey::new(n, e).map_err(Error::from)
    }

    pub fn kid(&self) -> String {
        self.kid.clone().unwrap_or_else(|| self.thumbprint())
    }
}

fn decode_uint(s: &str, _label: &'static str) -> Result<BigUint> {
    let bytes = b64::decode(s)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_jwk() -> Jwk {
        // 2048-bit keygen runs ~50-200ms; reuse one key across the cheap tests
        // by calling generate_rsa once per test (tests run in parallel so
        // amortising further isn't worth the complication).
        Jwk::generate_rsa(2048)
    }

    #[test]
    fn generate_has_thumbprint_kid() {
        let jwk = sample_jwk();
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.alg.as_deref(), Some("RS256"));
        assert_eq!(jwk.use_.as_deref(), Some("sig"));
        assert!(jwk.d.is_some());
        assert!(jwk.p.is_some());
        assert!(jwk.q.is_some());
        assert!(jwk.dp.is_some());
        assert!(jwk.dq.is_some());
        assert!(jwk.qi.is_some());
        assert_eq!(jwk.kid.as_deref().unwrap(), jwk.thumbprint());
    }

    #[test]
    fn to_public_strips_private_components() {
        let jwk = sample_jwk();
        let pub_jwk = jwk.to_public();
        assert!(pub_jwk.d.is_none());
        assert!(pub_jwk.p.is_none());
        assert!(pub_jwk.q.is_none());
        assert!(pub_jwk.dp.is_none());
        assert!(pub_jwk.dq.is_none());
        assert!(pub_jwk.qi.is_none());
        assert_eq!(pub_jwk.n, jwk.n);
        assert_eq!(pub_jwk.e, jwk.e);
        assert_eq!(pub_jwk.kid, jwk.kid);
    }

    #[test]
    fn signing_and_verifying_keys_roundtrip() {
        let jwk = sample_jwk();
        let sk = jwk.signing_key().unwrap();
        let vk = jwk.verifying_key().unwrap();
        assert_eq!(sk.n(), vk.n());
        assert_eq!(sk.e(), vk.e());
    }

    #[test]
    fn thumbprint_is_stable_across_public_strip() {
        let jwk = sample_jwk();
        let public = jwk.to_public();
        assert_eq!(jwk.thumbprint(), public.thumbprint());
    }
}
