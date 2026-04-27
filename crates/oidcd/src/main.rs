mod config;
mod discovery;
mod identity;
mod keystore;
mod state;
mod uds;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::{Config, DEFAULT_CONFIG_PATH};
use crate::keystore::KeyStore;
use crate::state::AppState;

#[derive(Parser, Debug)]
#[command(name = "keycard-osx-oidcd", version, about = "Local OIDC issuer for macOS")]
struct Cli {
    /// Path to the daemon config TOML.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Force key rotation: retire current key, generate a new one, exit.
    /// Run while the daemon is stopped.
    RotateKeys,
    /// Print the current public JWKS to stdout (for debugging).
    DumpJwks,
}

fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();

    match cli.command {
        Some(Command::RotateKeys) => rotate_keys(&cli.config),
        Some(Command::DumpJwks) => dump_jwks(&cli.config),
        None => run_daemon(&cli.config),
    }
}

fn init_logging() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_writer(std::io::stdout)
        .try_init();
}

fn load_config(path: &PathBuf) -> Result<Config> {
    Config::load(path).with_context(|| format!("loading config {}", path.display()))
}

fn open_keystore(cfg: &Config) -> Result<KeyStore> {
    KeyStore::open(&cfg.keys_dir, cfg.rotation_interval(), cfg.previous_key_grace())
        .with_context(|| format!("opening keystore at {}", cfg.keys_dir.display()))
}

fn rotate_keys(path: &PathBuf) -> Result<()> {
    let cfg = load_config(path)?;
    let mut keystore = open_keystore(&cfg)?;
    keystore.rotate()?;
    println!(
        "rotated. new kid={} previous_kid={}",
        keystore.current().kid(),
        keystore
            .previous_public()
            .map(|p| p.kid())
            .unwrap_or_default()
    );
    Ok(())
}

fn dump_jwks(path: &PathBuf) -> Result<()> {
    let cfg = load_config(path)?;
    let keystore = open_keystore(&cfg)?;
    println!("{}", serde_json::to_string_pretty(&keystore.jwks())?);
    Ok(())
}

fn run_daemon(path: &PathBuf) -> Result<()> {
    let cfg = load_config(path)?;
    let keystore = open_keystore(&cfg)?;
    tracing::info!(
        issuer = %cfg.issuer,
        listen_http = %cfg.listen_http,
        listen_uds = %cfg.listen_uds,
        kid = %keystore.current().kid(),
        "starting keycard-osx-oidcd"
    );
    if !is_loopback_listen(&cfg.listen_http) {
        tracing::warn!(
            listen_http = %cfg.listen_http,
            "HTTP listener is NOT bound to loopback; the discovery surface will be \
             reachable directly from the network. The token endpoint is still \
             UDS-only and unreachable from the network, but binding to a public \
             address bypasses Tailscale's TLS termination. Consider listen_http = \
             \"127.0.0.1:8080\"."
        );
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let app_state = Arc::new(AppState::new(cfg, keystore)?);

        let uds_state = Arc::clone(&app_state);
        let http_state = Arc::clone(&app_state);
        let rot_state = Arc::clone(&app_state);

        let uds_task = tokio::spawn(async move { uds::serve(uds_state).await });
        let http_task = tokio::spawn(async move { discovery::serve(http_state).await });
        let rotation_task = tokio::spawn(rotation_loop(rot_state));

        tokio::select! {
            r = uds_task => match r {
                Ok(inner) => inner.context("uds server exited"),
                Err(e) => Err(anyhow::Error::from(e).context("uds task panicked")),
            },
            r = http_task => match r {
                Ok(inner) => inner.context("http server exited"),
                Err(e) => Err(anyhow::Error::from(e).context("http task panicked")),
            },
            r = rotation_task => match r {
                Ok(inner) => inner.context("rotation task exited"),
                Err(e) => Err(anyhow::Error::from(e).context("rotation task panicked")),
            },
        }
    })
}

fn is_loopback_listen(listen: &str) -> bool {
    let host = listen.rsplit_once(':').map(|(h, _)| h).unwrap_or(listen);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

async fn rotation_loop(state: Arc<AppState>) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let mut keystore = state.keystore.write().await;
        if keystore.should_rotate() {
            match keystore.rotate() {
                Ok(()) => tracing::info!(new_kid = %keystore.current().kid(), "rotated keys"),
                Err(e) => tracing::error!(error = %e, "key rotation failed"),
            }
        }
        if let Err(e) = keystore.purge_expired_previous() {
            tracing::warn!(error = %e, "purge_expired_previous failed");
        }
    }
}
