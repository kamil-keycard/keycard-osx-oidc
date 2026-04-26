use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use oidc_core::protocol::{ErrorResponse, Request, Response, TokenResponse, WhoamiResponse};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const DEFAULT_SOCKET: &str = "/var/run/keycard-osx-oidcd.sock";

#[derive(Parser, Debug)]
#[command(name = "keycard-osx-oidc", version, about = "Local OIDC token client for macOS")]
struct Cli {
    /// Path to the daemon's Unix socket.
    #[arg(long, default_value = DEFAULT_SOCKET, env = "KEYCARD_OSX_OIDC_SOCKET")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print identity claims that the daemon would mint a token for. Does
    /// not produce a JWT.
    Whoami,
    /// Request a JWT bound to the requested audience.
    Token(TokenArgs),
}

#[derive(Parser, Debug)]
struct TokenArgs {
    /// Required audience claim, e.g. `sts.amazonaws.com`.
    #[arg(long)]
    audience: String,

    /// Requested TTL in seconds. Capped to the daemon's max_ttl_seconds.
    #[arg(long)]
    ttl_seconds: Option<u64>,

    /// Write the token (raw, no newline) to this file with mode 0600 instead
    /// of stdout.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Long-running mode: keep the file at `--output` fresh by re-requesting
    /// a token before it expires. Implies `--output`.
    #[arg(long, default_value_t = false)]
    watch: bool,

    /// Renew when the token has fewer than this many seconds of life left.
    /// Only used with `--watch`.
    #[arg(long, default_value_t = 300)]
    refresh_skew_seconds: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        match cli.command {
            Command::Whoami => cmd_whoami(&cli.socket).await,
            Command::Token(args) => cmd_token(&cli.socket, args).await,
        }
    })
}

async fn cmd_whoami(socket: &Path) -> Result<()> {
    let resp = round_trip(socket, &Request::Whoami).await?;
    match resp {
        Response::Whoami(w) => {
            print_whoami(&w);
            Ok(())
        }
        Response::Error(e) => Err(anyhow!("daemon error: {}", e.error)),
        _ => Err(anyhow!("unexpected response from daemon")),
    }
}

fn print_whoami(w: &WhoamiResponse) {
    println!("issuer:     {}", w.issuer);
    println!("sub:        {}", w.sub);
    println!("uid:        {}", w.uid);
    println!("username:   {}", w.username);
    println!("hostname:   {}", w.hostname);
    println!("machine_id: {}", w.machine_id);
}

async fn cmd_token(socket: &Path, args: TokenArgs) -> Result<()> {
    if args.watch && args.output.is_none() {
        bail!("--watch requires --output");
    }

    let request = Request::Token {
        audience: args.audience.clone(),
        ttl_seconds: args.ttl_seconds,
    };

    if !args.watch {
        let token = request_token(socket, &request).await?;
        emit(&token, args.output.as_deref())?;
        return Ok(());
    }

    let output = args.output.expect("checked above");
    loop {
        let token = request_token(socket, &request).await?;
        write_atomic_secret(&output, token.token.as_bytes())?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let life = (token.expires_at - now).max(0) as u64;
        let sleep_for = life.saturating_sub(args.refresh_skew_seconds).max(15);
        eprintln!(
            "wrote token to {} (kid={}, exp in {}s, refreshing in {}s)",
            output.display(),
            extract_kid(&token.token).unwrap_or_default(),
            life,
            sleep_for
        );
        tokio::time::sleep(Duration::from_secs(sleep_for)).await;
    }
}

async fn request_token(socket: &Path, req: &Request) -> Result<TokenResponse> {
    match round_trip(socket, req).await? {
        Response::Token(t) => Ok(t),
        Response::Error(ErrorResponse { error }) => Err(anyhow!("daemon error: {error}")),
        _ => Err(anyhow!("unexpected response from daemon")),
    }
}

async fn round_trip(socket: &Path, req: &Request) -> Result<Response> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to {}", socket.display()))?;
    let (read_half, mut write_half) = stream.into_split();

    let mut payload = serde_json::to_vec(req)?;
    payload.push(b'\n');
    write_half.write_all(&payload).await?;
    write_half.shutdown().await?;

    let mut lines = BufReader::new(read_half).lines();
    let line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("daemon closed without responding"))?;
    let resp: Response = serde_json::from_str(&line)
        .with_context(|| format!("parsing daemon response: {line}"))?;
    Ok(resp)
}

fn emit(token: &TokenResponse, output: Option<&Path>) -> Result<()> {
    match output {
        Some(p) => write_atomic_secret(p, token.token.as_bytes()),
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(token.token.as_bytes())?;
            out.write_all(b"\n")?;
            Ok(())
        }
    }
}

fn write_atomic_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn extract_kid(token: &str) -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let header_b64 = token.split('.').next()?;
    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    header.get("kid").and_then(|k| k.as_str()).map(str::to_owned)
}
