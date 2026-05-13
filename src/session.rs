use crate::crypto::{decode, encode, VaultKey};
use crate::storage::set_private_file_permissions;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const APP_DIR: &str = "rust_keystore";
const SESSION_FILE: &str = "session.json";
const SESSION_TTL_SECONDS: u64 = 12 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    version: u8,
    key: String,
    pub active_group: String,
    expires_at: u64,
}

impl Session {
    pub fn new(key: &VaultKey, active_group: &str) -> Result<Self> {
        Ok(Self {
            version: 1,
            key: encode(key),
            active_group: active_group.to_string(),
            expires_at: now_seconds()? + SESSION_TTL_SECONDS,
        })
    }

    pub fn key(&self) -> Result<VaultKey> {
        if self.version != 1 {
            return Err(anyhow!("unsupported session version {}", self.version));
        }
        if self.expires_at < now_seconds()? {
            return Err(anyhow!("session expired; run `ks login` again"));
        }

        let decoded = decode(&self.key, "session key")?;
        let key: VaultKey = decoded
            .try_into()
            .map_err(|_| anyhow!("session key has invalid length; run `ks login` again"))?;
        Ok(key)
    }
}

pub fn load() -> Result<Session> {
    let path = session_path()?;
    let content = fs::read_to_string(&path).context("not logged in; run `ks login` first")?;
    serde_json::from_str(&content).context("failed to parse session; run `ks login` again")
}

pub fn save(session: &Session) -> Result<()> {
    let path = session_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create config directory")?;
    }
    let content = serde_json::to_string_pretty(session).context("failed to encode session")?;
    fs::write(&path, content).context("failed to write session")?;
    set_private_file_permissions(&path)?;
    Ok(())
}

pub fn clear() -> Result<bool> {
    let path = session_path()?;
    if path.exists() {
        fs::remove_file(path).context("failed to remove session")?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn session_path() -> Result<PathBuf> {
    let mut path = dirs::config_dir().ok_or_else(|| anyhow!("could not find config directory"))?;
    path.push(APP_DIR);
    path.push(SESSION_FILE);
    Ok(path)
}

fn now_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}
