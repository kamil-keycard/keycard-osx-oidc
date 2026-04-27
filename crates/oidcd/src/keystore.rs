//! On-disk key store for the daemon's signing key.
//!
//! Layout under the configured base directory (default
//! `/var/db/keycard-osx-oidcd/keys`):
//!
//! - `current.json`  — full RSA JWK including the private components.
//!                     Mode `0600`, owner `root`.
//! - `previous.json` — public-only JWK retained during the grace window so
//!                     verifiers caching JWKS can still validate freshly
//!                     issued tokens whose `kid` was rotated out.
//! - `meta.json`     — sidecar with rotation timestamps; tells us when the
//!                     current key was created and when the previous key was
//!                     retired.
//!
//! The daemon never edits these files in place: writes go to a sibling
//! `.tmp` and are renamed atomically.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use oidc_core::{Jwk, Jwks};
use serde::{Deserialize, Serialize};

const CURRENT_FILE: &str = "current.json";
const PREVIOUS_FILE: &str = "previous.json";
const META_FILE: &str = "meta.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Meta {
    /// Unix-epoch seconds at which `current.json` was generated.
    current_created_at: u64,
    /// Unix-epoch seconds at which `previous.json` was rotated out, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    previous_retired_at: Option<u64>,
}

#[derive(Debug)]
pub struct KeyStore {
    dir: PathBuf,
    current: Jwk,
    previous: Option<Jwk>,
    meta: Meta,
    rotation_interval: Duration,
    grace: Duration,
}

impl KeyStore {
    /// Open the keystore at `dir`. If `current.json` is missing, generate a
    /// fresh signing key. Expired previous keys (older than `grace`) are
    /// purged from disk on load.
    pub fn open(
        dir: impl Into<PathBuf>,
        rotation_interval: Duration,
        grace: Duration,
    ) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating key dir {}", dir.display()))?;
        // Tighten directory mode to 0700; safe to call repeatedly.
        let mut perms = fs::metadata(&dir)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&dir, perms)?;

        let mut meta: Meta = read_json(&dir.join(META_FILE))?.unwrap_or_default();

        let current = match read_json::<Jwk>(&dir.join(CURRENT_FILE))? {
            Some(jwk) => jwk,
            None => {
                let jwk = Jwk::generate_rsa(2048);
                write_secret_json(&dir.join(CURRENT_FILE), &jwk)?;
                meta.current_created_at = unix_now();
                meta.previous_retired_at = None;
                write_json(&dir.join(META_FILE), &meta)?;
                jwk
            }
        };
        if meta.current_created_at == 0 {
            // Pre-existing current.json with no meta; record now so rotation
            // logic doesn't immediately fire.
            meta.current_created_at = unix_now();
            write_json(&dir.join(META_FILE), &meta)?;
        }

        let previous = read_json::<Jwk>(&dir.join(PREVIOUS_FILE))?;
        let previous = match (previous, meta.previous_retired_at) {
            (Some(jwk), Some(retired_at)) if unix_now() < retired_at + grace.as_secs() => {
                Some(jwk)
            }
            (Some(_), _) => {
                let _ = fs::remove_file(dir.join(PREVIOUS_FILE));
                meta.previous_retired_at = None;
                write_json(&dir.join(META_FILE), &meta)?;
                None
            }
            (None, _) => {
                if meta.previous_retired_at.is_some() {
                    meta.previous_retired_at = None;
                    write_json(&dir.join(META_FILE), &meta)?;
                }
                None
            }
        };

        Ok(Self {
            dir,
            current,
            previous,
            meta,
            rotation_interval,
            grace,
        })
    }

    pub fn current(&self) -> &Jwk {
        &self.current
    }

    pub fn previous_public(&self) -> Option<&Jwk> {
        self.previous.as_ref()
    }

    /// Public JWKS document for `/.well-known/jwks.json`.
    pub fn jwks(&self) -> Jwks {
        let mut keys = vec![self.current.to_public()];
        if let Some(prev) = &self.previous {
            keys.push(prev.to_public());
        }
        Jwks { keys }
    }

    /// True if `current` has lived longer than the configured rotation
    /// interval and should be replaced.
    pub fn should_rotate(&self) -> bool {
        unix_now() >= self.meta.current_created_at + self.rotation_interval.as_secs()
    }

    /// Generate a new signing key, retire the existing one to `previous.json`
    /// (public component only), and persist the new state atomically.
    pub fn rotate(&mut self) -> Result<()> {
        let retired_public = self.current.to_public();
        write_secret_json(&self.dir.join(PREVIOUS_FILE), &retired_public)?;

        let new_current = Jwk::generate_rsa(2048);
        write_secret_json(&self.dir.join(CURRENT_FILE), &new_current)?;

        self.previous = Some(retired_public);
        self.current = new_current;
        self.meta.previous_retired_at = Some(unix_now());
        self.meta.current_created_at = unix_now();
        write_json(&self.dir.join(META_FILE), &self.meta)?;

        Ok(())
    }

    /// Drop a previous key whose grace window has fully elapsed. Cheap to
    /// call from the rotation tick.
    pub fn purge_expired_previous(&mut self) -> Result<()> {
        if let Some(retired_at) = self.meta.previous_retired_at {
            if unix_now() >= retired_at + self.grace.as_secs() {
                let _ = fs::remove_file(self.dir.join(PREVIOUS_FILE));
                self.previous = None;
                self.meta.previous_retired_at = None;
                write_json(&self.dir.join(META_FILE), &self.meta)?;
            }
        }
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match File::open(path) {
        Ok(mut f) => {
            let mut buf = String::new();
            f.read_to_string(&mut buf)
                .with_context(|| format!("reading {}", path.display()))?;
            let value = serde_json::from_str(&buf)
                .with_context(|| format!("parsing {}", path.display()))?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::from(e).context(format!("opening {}", path.display()))),
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_atomic(path, &serde_json::to_vec_pretty(value)?, 0o644)
}

fn write_secret_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_atomic(path, &serde_json::to_vec_pretty(value)?, 0o600)
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn store(dir: &Path) -> KeyStore {
        KeyStore::open(dir, Duration::from_secs(7 * 24 * 3600), Duration::from_secs(24 * 3600))
            .unwrap()
    }

    #[test]
    fn first_open_creates_current_only() {
        let tmp = tempdir().unwrap();
        let s = store(tmp.path());
        assert!(tmp.path().join("current.json").exists());
        assert!(!tmp.path().join("previous.json").exists());
        assert!(s.previous_public().is_none());
        assert_eq!(s.jwks().keys.len(), 1);
    }

    #[test]
    fn second_open_reuses_existing_key() {
        let tmp = tempdir().unwrap();
        let kid_first = store(tmp.path()).current().kid();
        let kid_second = store(tmp.path()).current().kid();
        assert_eq!(kid_first, kid_second);
    }

    #[test]
    fn rotate_promotes_current_to_previous_public_only() {
        let tmp = tempdir().unwrap();
        let mut s = store(tmp.path());
        let old_kid = s.current().kid();
        s.rotate().unwrap();
        assert_ne!(s.current().kid(), old_kid);
        let prev = s.previous_public().expect("previous after rotate");
        assert_eq!(prev.kid(), old_kid);
        assert!(prev.d.is_none(), "previous must not retain private d");
        let jwks = s.jwks();
        assert_eq!(jwks.keys.len(), 2);
        for k in &jwks.keys {
            assert!(k.d.is_none());
        }
    }

    #[test]
    fn purge_drops_previous_after_grace() {
        let tmp = tempdir().unwrap();
        let mut s = KeyStore::open(
            tmp.path(),
            Duration::from_secs(60),
            Duration::from_secs(0), // zero grace
        )
        .unwrap();
        s.rotate().unwrap();
        assert!(s.previous_public().is_some());
        s.purge_expired_previous().unwrap();
        assert!(s.previous_public().is_none());
        assert!(!tmp.path().join("previous.json").exists());
    }

    #[test]
    fn open_purges_stale_previous() {
        let tmp = tempdir().unwrap();
        // First, create + rotate with zero grace so previous immediately stale.
        {
            let mut s = KeyStore::open(
                tmp.path(),
                Duration::from_secs(60),
                Duration::from_secs(0),
            )
            .unwrap();
            s.rotate().unwrap();
            // previous file exists on disk
            assert!(tmp.path().join("previous.json").exists());
        }
        // Re-open; should detect stale previous and purge it.
        let s2 = KeyStore::open(
            tmp.path(),
            Duration::from_secs(60),
            Duration::from_secs(0),
        )
        .unwrap();
        assert!(s2.previous_public().is_none());
        assert!(!tmp.path().join("previous.json").exists());
    }

    #[test]
    fn current_file_has_mode_0600() {
        let tmp = tempdir().unwrap();
        let _ = store(tmp.path());
        let mode = fs::metadata(tmp.path().join("current.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn should_rotate_only_after_interval() {
        let tmp = tempdir().unwrap();
        let s = KeyStore::open(
            tmp.path(),
            Duration::from_secs(3600),
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(!s.should_rotate());

        let s2 = KeyStore::open(
            tmp.path(),
            Duration::from_secs(0),
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(s2.should_rotate());
    }
}
