//! OIDC discovery document shape served at
//! `/.well-known/openid-configuration`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub claims_supported: Vec<String>,
}

impl DiscoveryDocument {
    pub fn for_issuer(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            jwks_uri: format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')),
            id_token_signing_alg_values_supported: vec!["RS256".into()],
            subject_types_supported: vec!["public".into()],
            response_types_supported: vec!["id_token".into()],
            claims_supported: vec![
                "sub".into(),
                "iss".into(),
                "aud".into(),
                "iat".into(),
                "nbf".into(),
                "exp".into(),
                "uid".into(),
                "username".into(),
                "hostname".into(),
                "machine_id".into(),
            ],
        }
    }
}
