//! Shared, in-memory daemon state.
//!
//! Holds the loaded config, host identity, and the keystore behind a tokio
//! `RwLock` so the rotation tick can swap keys without blocking readers.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::identity;
use crate::keystore::KeyStore;

#[derive(Debug)]
pub struct AppState {
    pub config: Arc<Config>,
    pub keystore: RwLock<KeyStore>,
    pub hostname: String,
    pub machine_id: String,
}

impl AppState {
    pub fn new(config: Config, keystore: KeyStore) -> Result<Self> {
        Ok(Self {
            config: Arc::new(config),
            keystore: RwLock::new(keystore),
            hostname: identity::hostname()?,
            machine_id: identity::machine_uuid()?,
        })
    }

    pub fn sub_for(&self, uid: u32) -> String {
        format!("{}:{}", self.machine_id, uid)
    }
}
