//! Shared OIDC types for keycard-osx-oidc.
//!
//! This crate is free of macOS-specific behaviour and can be unit-tested in
//! isolation. It owns:
//!
//! - `Jwk` / `Jwks` (RFC 7517) for Ed25519 (`OKP` / `Ed25519`)
//! - JWK thumbprint computation per RFC 7638 used as the `kid`
//! - The `Claims` type emitted by the daemon
//! - The sign / verify primitives that turn `Claims` into a compact JWT
