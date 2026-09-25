use crate::api_keys;
use crate::crypto::{decode, encode, VaultKey};
use crate::storage::set_private_file_permissions;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
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
    save_at_path(&session_path()?, session)
}

fn save_at_path(path: &Path, session: &Session) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create config directory")?;
    }
    let content = serde_json::to_string_pretty(session).context("failed to encode session")?;
    let temp_path = path.with_extension(format!("{}.tmp", api_keys::new_id()));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temp_path)
            .context("failed to create temporary session")?;
        set_private_file_permissions(&temp_path)?;
        file.write_all(content.as_bytes())
            .context("failed to write session")?;
        file.sync_all().context("failed to sync session")?;
        fs::rename(&temp_path, path).context("failed to replace session")?;
        #[cfg(unix)]
        fs::File::open(path.parent().unwrap())
            .and_then(|parent| parent.sync_all())
            .context("failed to sync session directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

pub fn clear() -> Result<bool> {
    let path = session_path()?;
    if path.exists() {
        fs::remove_file(&path).context("failed to remove session")?;
        #[cfg(unix)]
        fs::File::open(path.parent().unwrap())
            .and_then(|parent| parent.sync_all())
            .context("failed to sync session directory")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_file_is_private_and_replaced_atomically() {
        let directory =
            std::env::temp_dir().join(format!("ks-session-test-{}", api_keys::new_id()));
        let path = directory.join("session.json");
        let mut session = Session::new(&[0; 32], "default").unwrap();
        save_at_path(&path, &session).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        session.active_group = "work".into();
        save_at_path(&path, &session).unwrap();
        let loaded: Session = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.active_group, "work");
        fs::remove_dir_all(directory).unwrap();
    }
}
