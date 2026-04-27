use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid jwk: {0}")]
    InvalidJwk(&'static str),

    #[error("invalid jwt: {0}")]
    InvalidJwt(&'static str),

    #[error("signature verification failed")]
    BadSignature,

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("rsa error: {0}")]
    Rsa(#[from] rsa::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
