//! Unix-domain-socket token endpoint.
//!
//! Identity binding is *implicit*: the daemon trusts the kernel's report of
//! the connecting peer's UID via `peer_cred` (which on macOS calls
//! `getpeereid`). The CLI on the other end of the socket does not need —
//! and is not given — any way to assert a different identity.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use oidc_core::protocol::{
    ErrorResponse, Request, Response, TokenResponse, WhoamiResponse,
};
use oidc_core::{jwt, Claims};
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::identity;
use crate::state::AppState;

pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let path = state.config.listen_uds.clone();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("binding UDS at {path}"))?;

    // Anyone on the box should be able to connect; the daemon enforces
    // identity at request time via getpeereid.
    let mut perms = std::fs::metadata(&path)?.permissions();
    perms.set_mode(0o666);
    std::fs::set_permissions(&path, perms)?;

    tracing::info!(socket = %path, "uds listener ready");

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "uds accept failed");
                continue;
            }
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(state, stream).await {
                tracing::warn!(error = %e, "uds connection error");
            }
        });
    }
}

async fn handle_connection(state: Arc<AppState>, stream: UnixStream) -> Result<()> {
    let cred = stream
        .peer_cred()
        .context("peer_cred (getpeereid) failed")?;
    let uid = cred.uid();

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    let request_line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("client closed before sending request"))?;

    let response = match serde_json::from_str::<Request>(&request_line) {
        Ok(req) => handle_request(&state, uid, req).await,
        Err(e) => Response::Error(ErrorResponse {
            error: format!("invalid request: {e}"),
        }),
    };

    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    write_half.write_all(&bytes).await?;
    write_half.flush().await?;
    Ok(())
}

async fn handle_request(state: &Arc<AppState>, uid: u32, req: Request) -> Response {
    match req {
        Request::Whoami => match build_whoami(state, uid) {
            Ok(w) => Response::Whoami(w),
            Err(e) => Response::Error(ErrorResponse { error: e.to_string() }),
        },
        Request::Token { audience, ttl_seconds } => {
            match build_token(state, uid, &audience, ttl_seconds).await {
                Ok(t) => Response::Token(t),
                Err(e) => Response::Error(ErrorResponse { error: e.to_string() }),
            }
        }
    }
}

fn build_whoami(state: &Arc<AppState>, uid: u32) -> Result<WhoamiResponse> {
    let username = identity::username_for_uid(uid)?;
    Ok(WhoamiResponse {
        sub: state.sub_for(uid),
        uid,
        username,
        hostname: state.hostname.clone(),
        machine_id: state.machine_id.clone(),
        issuer: state.config.issuer.clone(),
    })
}

async fn build_token(
    state: &Arc<AppState>,
    uid: u32,
    audience: &str,
    ttl_seconds: Option<u64>,
) -> Result<TokenResponse> {
    if audience.is_empty() {
        return Err(anyhow!("audience required"));
    }
    if !state.config.audience_allowed(audience) {
        return Err(anyhow!("audience '{audience}' not allowed"));
    }

    let ttl = ttl_seconds
        .unwrap_or(state.config.default_ttl_seconds)
        .min(state.config.max_ttl_seconds);
    if ttl == 0 {
        return Err(anyhow!("ttl_seconds must be > 0"));
    }

    let username = identity::username_for_uid(uid)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let exp = now + ttl as i64;

    let claims = Claims {
        iss: state.config.issuer.clone(),
        sub: state.sub_for(uid),
        aud: audience.to_string(),
        iat: now,
        nbf: now,
        exp,
        uid,
        username,
        hostname: state.hostname.clone(),
        machine_id: state.machine_id.clone(),
    };

    let keystore = state.keystore.read().await;
    let token = jwt::sign(keystore.current(), &claims)?;
    drop(keystore);

    Ok(TokenResponse {
        token,
        expires_at: exp,
        claims,
    })
}

/// Helper for tests: bind a socket, run `serve` in the background, return
/// its path.
#[cfg(test)]
pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}
