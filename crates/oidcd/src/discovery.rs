//! Public-facing HTTP server: OIDC discovery + JWKS.
//!
//! Bound to `127.0.0.1` only; Tailscale (`tailscale serve` / `funnel`)
//! terminates TLS in front of it.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use oidc_core::{DiscoveryDocument, Jwks};

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(openid_config))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/healthz", get(healthz))
        .with_state(state)
}

pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let addr = state.config.listen_http.clone();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding HTTP listener at {addr}"))?;
    tracing::info!(addr = %addr, "discovery http listener ready");
    let app = router(Arc::clone(&state));
    axum::serve(listener, app).await.context("axum::serve")?;
    Ok(())
}

async fn openid_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let doc = DiscoveryDocument::for_issuer(&state.config.issuer);
    cached_json(StatusCode::OK, &doc)
}

async fn jwks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let keystore = state.keystore.read().await;
    let jwks: Jwks = keystore.jwks();
    cached_json(StatusCode::OK, &jwks)
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

fn cached_json<T: serde::Serialize>(status: StatusCode, body: &T) -> axum::response::Response {
    let mut resp = (status, Json(body)).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::keystore::KeyStore;
    use axum::body::Body;
    use axum::http::Request;
    use std::time::Duration;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn test_state(issuer: &str) -> Arc<AppState> {
        let tmp = tempdir().unwrap();
        let cfg = Config {
            issuer: issuer.into(),
            listen_http: "127.0.0.1:0".into(),
            listen_uds: "/tmp/never".into(),
            keys_dir: tmp.path().to_path_buf(),
            default_ttl_seconds: 3600,
            max_ttl_seconds: 7200,
            allowed_audiences: vec![],
            rotation_interval_days: 7,
            previous_key_grace_hours: 24,
        };
        let keystore = KeyStore::open(
            tmp.path(),
            Duration::from_secs(7 * 24 * 3600),
            Duration::from_secs(24 * 3600),
        )
        .unwrap();
        // Tempdir is intentionally leaked into the AppState lifetime here;
        // tests are short-lived and cleanup happens at process exit.
        std::mem::forget(tmp);
        Arc::new(AppState {
            config: Arc::new(cfg),
            keystore: tokio::sync::RwLock::new(keystore),
            hostname: "host".into(),
            machine_id: "MID".into(),
        })
    }

    #[tokio::test]
    async fn openid_configuration_includes_issuer_and_jwks_uri() {
        let state = test_state("https://issuer.example");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["issuer"], "https://issuer.example");
        assert_eq!(v["jwks_uri"], "https://issuer.example/.well-known/jwks.json");
        assert!(v["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "RS256"));
    }

    #[tokio::test]
    async fn jwks_returns_public_only() {
        let state = test_state("https://issuer.example");
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let keys = v["keys"].as_array().expect("keys array");
        assert!(!keys.is_empty());
        for k in keys {
            assert!(k.get("d").is_none(), "jwks must not expose private d");
            assert!(k.get("p").is_none(), "jwks must not expose prime p");
            assert!(k.get("q").is_none(), "jwks must not expose prime q");
            assert_eq!(k["kty"], "RSA");
            assert!(k.get("n").is_some(), "jwks must include modulus n");
            assert!(k.get("e").is_some(), "jwks must include exponent e");
            assert!(k.get("crv").is_none(), "RSA jwks must not include crv");
        }
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let state = test_state("https://issuer.example");
        let app = router(state);
        let resp = app
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
