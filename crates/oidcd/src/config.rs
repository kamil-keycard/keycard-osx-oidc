//! `/etc/keycard-osx-oidcd/config.toml` shape and loader.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/keycard-osx-oidcd/config.toml";
pub const DEFAULT_KEYS_DIR: &str = "/var/db/keycard-osx-oidcd/keys";
pub const DEFAULT_LISTEN_HTTP: &str = "127.0.0.1:8080";
pub const DEFAULT_LISTEN_UDS: &str = "/var/run/keycard-osx-oidcd.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Externally-reachable issuer URL. Must match the URL Tailscale serves.
    pub issuer: String,
    #[serde(default = "default_listen_http")]
    pub listen_http: String,
    #[serde(default = "default_listen_uds")]
    pub listen_uds: String,
    #[serde(default = "default_keys_dir")]
    pub keys_dir: PathBuf,
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: u64,
    #[serde(default = "max_ttl_seconds_default")]
    pub max_ttl_seconds: u64,
    /// Empty means "any audience allowed".
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    #[serde(default = "default_rotation_days")]
    pub rotation_interval_days: u64,
    #[serde(default = "default_grace_hours")]
    pub previous_key_grace_hours: u64,
}

fn default_listen_http() -> String {
    DEFAULT_LISTEN_HTTP.to_string()
}
fn default_listen_uds() -> String {
    DEFAULT_LISTEN_UDS.to_string()
}
fn default_keys_dir() -> PathBuf {
    PathBuf::from(DEFAULT_KEYS_DIR)
}
fn default_ttl_seconds() -> u64 {
    3600
}
fn max_ttl_seconds_default() -> u64 {
    12 * 3600
}
fn default_rotation_days() -> u64 {
    7
}
fn default_grace_hours() -> u64 {
    24
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading config at {}", path.display()))?;
        let cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing config at {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.issuer.is_empty() {
            bail!("config: `issuer` is required");
        }
        if !self.issuer.starts_with("https://") {
            bail!(
                "config: `issuer` must start with https:// (got {:?})",
                self.issuer
            );
        }
        if self.default_ttl_seconds == 0 {
            bail!("config: `default_ttl_seconds` must be > 0");
        }
        if self.max_ttl_seconds < self.default_ttl_seconds {
            bail!("config: `max_ttl_seconds` must be >= `default_ttl_seconds`");
        }
        if self.rotation_interval_days == 0 {
            bail!("config: `rotation_interval_days` must be > 0");
        }
        Ok(())
    }

    pub fn rotation_interval(&self) -> Duration {
        Duration::from_secs(self.rotation_interval_days * 24 * 3600)
    }

    pub fn previous_key_grace(&self) -> Duration {
        Duration::from_secs(self.previous_key_grace_hours * 3600)
    }

    pub fn audience_allowed(&self, audience: &str) -> bool {
        self.allowed_audiences.is_empty()
            || self.allowed_audiences.iter().any(|a| a == audience)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write(contents: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn loads_minimal_config() {
        let f = write(r#"issuer = "https://host.tail.ts.net""#);
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.issuer, "https://host.tail.ts.net");
        assert_eq!(cfg.listen_http, DEFAULT_LISTEN_HTTP);
        assert_eq!(cfg.listen_uds, DEFAULT_LISTEN_UDS);
        assert_eq!(cfg.default_ttl_seconds, 3600);
        assert_eq!(cfg.max_ttl_seconds, 12 * 3600);
        assert_eq!(cfg.rotation_interval_days, 7);
        assert_eq!(cfg.previous_key_grace_hours, 24);
        assert!(cfg.allowed_audiences.is_empty());
    }

    #[test]
    fn audience_allowlist_open_when_empty() {
        let cfg = Config {
            issuer: "https://x".into(),
            listen_http: default_listen_http(),
            listen_uds: default_listen_uds(),
            keys_dir: default_keys_dir(),
            default_ttl_seconds: 3600,
            max_ttl_seconds: 7200,
            allowed_audiences: vec![],
            rotation_interval_days: 7,
            previous_key_grace_hours: 24,
        };
        assert!(cfg.audience_allowed("anything"));
    }

    #[test]
    fn audience_allowlist_enforced_when_set() {
        let cfg = Config {
            issuer: "https://x".into(),
            listen_http: default_listen_http(),
            listen_uds: default_listen_uds(),
            keys_dir: default_keys_dir(),
            default_ttl_seconds: 3600,
            max_ttl_seconds: 7200,
            allowed_audiences: vec!["sts.amazonaws.com".into()],
            rotation_interval_days: 7,
            previous_key_grace_hours: 24,
        };
        assert!(cfg.audience_allowed("sts.amazonaws.com"));
        assert!(!cfg.audience_allowed("vault"));
    }

    #[test]
    fn rejects_non_https_issuer() {
        let f = write(r#"issuer = "http://insecure""#);
        assert!(Config::load(f.path()).is_err());
    }

    #[test]
    fn rejects_missing_issuer() {
        let f = write("");
        assert!(Config::load(f.path()).is_err());
    }
}
