//! End-to-end test: spawn the daemon binary, hit both surfaces over their
//! real listeners, and verify the issued JWT against the JWKS served at
//! `/.well-known/jwks.json` -- the same flow an external verifier follows.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use oidc_core::jwt;
use oidc_core::protocol::{Request, Response};
use oidc_core::{Jwk, Jwks};

fn cargo_bin(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR points at crates/oidcd; the workspace target dir is
    // resolved by Cargo via env CARGO_TARGET_DIR or default.
    if let Ok(custom) = std::env::var("CARGO_TARGET_DIR") {
        p = PathBuf::from(custom);
    } else {
        // Walk up to workspace root and append target/.
        p = p.parent().unwrap().parent().unwrap().join("target");
    }
    p.push("debug");
    p.push(name);
    p
}

fn pick_port() -> u16 {
    use std::net::TcpListener;
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn wait_for_http(url: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(resp) = ureq::get(url).call() {
            if resp.status() == 200 {
                return;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon did not become ready at {url}");
}

#[test]
fn end_to_end_token_verifies_against_published_jwks() {
    let port = pick_port();
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("sock");
    let cfg_path = tmp.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"issuer = "https://e2e.example"
listen_http = "127.0.0.1:{port}"
listen_uds  = "{sock}"
keys_dir    = "{keys}"
default_ttl_seconds = 60
max_ttl_seconds     = 600
allowed_audiences = ["e2e-aud"]
rotation_interval_days   = 7
previous_key_grace_hours = 24
"#,
            sock = sock.display(),
            keys = tmp.path().join("keys").display(),
        ),
    )
    .unwrap();

    let bin = cargo_bin("keycard-osx-oidcd");
    assert!(bin.exists(), "daemon binary not built at {}", bin.display());

    let mut daemon = Command::new(&bin)
        .arg("--config")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");

    let _kill = KillOnDrop(&mut daemon);

    let openid_url = format!("http://127.0.0.1:{port}/.well-known/openid-configuration");
    wait_for_http(&openid_url, Duration::from_secs(5));

    // Pull JWKS, like a real verifier would.
    let jwks_url = format!("http://127.0.0.1:{port}/.well-known/jwks.json");
    let jwks: Jwks = ureq::get(&jwks_url).call().unwrap().into_json().unwrap();
    assert_eq!(jwks.keys.len(), 1);
    for k in &jwks.keys {
        assert!(k.d.is_none(), "private d must not appear in published jwks");
    }

    // Mint a token via the UDS.
    let token = mint_token(&sock, "e2e-aud");

    // Verify it using the public key from JWKS -- exactly what jwt-cli does.
    let header_kid = decode_header_kid(&token).expect("kid in header");
    let jwk: &Jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid() == header_kid)
        .expect("kid present in jwks");
    let claims = jwt::verify(jwk, &token).expect("verify with jwks key");

    assert_eq!(claims.iss, "https://e2e.example");
    assert_eq!(claims.aud, "e2e-aud");
    assert_eq!(claims.uid, unsafe { libc::getuid() });
    assert!(claims.sub.contains(':'));
    assert!(claims.exp > claims.iat);
}

#[test]
fn end_to_end_rejects_disallowed_audience() {
    let port = pick_port();
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("sock");
    let cfg_path = tmp.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"issuer = "https://e2e.example"
listen_http = "127.0.0.1:{port}"
listen_uds  = "{sock}"
keys_dir    = "{keys}"
default_ttl_seconds = 60
max_ttl_seconds     = 600
allowed_audiences = ["only-this"]
rotation_interval_days   = 7
previous_key_grace_hours = 24
"#,
            sock = sock.display(),
            keys = tmp.path().join("keys").display(),
        ),
    )
    .unwrap();

    let bin = cargo_bin("keycard-osx-oidcd");
    let mut daemon = Command::new(&bin)
        .arg("--config")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let _kill = KillOnDrop(&mut daemon);
    wait_for_http(
        &format!("http://127.0.0.1:{port}/healthz"),
        Duration::from_secs(5),
    );

    let resp = round_trip(
        &sock,
        &Request::Token {
            audience: "nope".into(),
            ttl_seconds: None,
        },
    );
    match resp {
        Response::Error(e) => assert!(e.error.contains("not allowed"), "{e:?}"),
        other => panic!("expected error, got {other:?}"),
    }
}

fn mint_token(sock: &std::path::Path, audience: &str) -> String {
    let resp = round_trip(
        sock,
        &Request::Token {
            audience: audience.into(),
            ttl_seconds: None,
        },
    );
    match resp {
        Response::Token(t) => t.token,
        other => panic!("expected token response, got {other:?}"),
    }
}

fn round_trip(sock: &std::path::Path, req: &Request) -> Response {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(sock).expect("connect uds");
    let mut payload = serde_json::to_vec(req).unwrap();
    payload.push(b'\n');
    stream.write_all(&payload).unwrap();
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).expect("parse response")
}

fn decode_header_kid(token: &str) -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let header_b64 = token.split('.').next()?;
    let bytes = URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("kid").and_then(|s| s.as_str()).map(str::to_owned)
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl<'a> Drop for KillOnDrop<'a> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
