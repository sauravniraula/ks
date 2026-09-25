use crate::api_keys::{self, Access, ApiKey};
use crate::crypto::{
    decode, decrypt_json, derive_key, encode, encrypt_json, random_salt, VaultKey,
};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const APP_DIR: &str = "rust_keystore";
const VAULT_FILE: &str = "vault.json";
const LEGACY_FILE: &str = "keyvalues";
const DEFAULT_GROUP: &str = "default";
const ENVELOPE_VERSION: u8 = 1;
const KDF_NAME: &str = "argon2id";
const CIPHER_NAME: &str = "xchacha20poly1305";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub active_group: String,
    pub groups: BTreeMap<String, Group>,
    #[serde(default)]
    pub api_keys: BTreeMap<String, ApiKey>,
    #[serde(default)]
    pub api_signing_key: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Group {
    pub secrets: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultEnvelope {
    version: u8,
    kdf: String,
    cipher: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyKeyStore {
    data: BTreeMap<String, String>,
}

pub struct VaultStore {
    path: PathBuf,
}

pub struct UnlockedVault {
    store: VaultStore,
    data: VaultData,
    key: VaultKey,
    salt: Vec<u8>,
    last_saved_nonce: Cell<Option<[u8; 24]>>,
    write_uncertain: Cell<bool>,
}

impl Default for VaultData {
    fn default() -> Self {
        let mut groups = BTreeMap::new();
        groups.insert(DEFAULT_GROUP.to_string(), Group::default());
        Self {
            active_group: DEFAULT_GROUP.to_string(),
            groups,
            api_keys: BTreeMap::new(),
            api_signing_key: None,
        }
    }
}

impl VaultStore {
    pub fn new() -> Result<Self> {
        let mut path =
            dirs::config_dir().ok_or_else(|| anyhow!("could not find config directory"))?;
        path.push(APP_DIR);
        path.push(VAULT_FILE);
        Ok(Self { path })
    }

    #[cfg(test)]
    pub(crate) fn for_test(path: PathBuf) -> Self {
        Self { path }
    }

    fn legacy_path(&self) -> PathBuf {
        let mut path = self.path.clone();
        path.set_file_name(LEGACY_FILE);
        path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn create(&self, password: &str) -> Result<UnlockedVault> {
        if self.exists() {
            return Err(anyhow!("vault already exists"));
        }

        let salt = random_salt();
        let key = derive_key(password, &salt)?;
        let legacy_path = self.legacy_path();
        let data = if legacy_path.exists() {
            let content = fs::read_to_string(&legacy_path)
                .context("failed to read legacy plaintext store")?;
            let legacy: LegacyKeyStore =
                serde_json::from_str(&content).context("failed to parse legacy plaintext store")?;
            let mut data = VaultData::default();
            if let Some(group) = data.groups.get_mut(DEFAULT_GROUP) {
                group.secrets = legacy.data;
            }
            data
        } else {
            VaultData::default()
        };

        let unlocked = UnlockedVault {
            store: self.clone(),
            data,
            key,
            salt: salt.to_vec(),
            last_saved_nonce: Cell::new(None),
            write_uncertain: Cell::new(false),
        };
        unlocked.save()?;
        if legacy_path.exists() {
            fs::remove_file(&legacy_path).context(
                "encrypted vault was created, but failed to remove legacy plaintext store",
            )?;
        }
        Ok(unlocked)
    }

    pub fn unlock(&self, password: &str) -> Result<UnlockedVault> {
        let envelope = self.read_envelope()?;
        let salt = decode(&envelope.salt, "salt")?;
        let nonce = decode(&envelope.nonce, "nonce")?;
        let ciphertext = decode(&envelope.ciphertext, "ciphertext")?;
        let key = derive_key(password, &salt)?;
        self.open_with_key_material(key, salt, &nonce, &ciphertext)
    }

    pub fn unlock_with_key(&self, key: VaultKey) -> Result<UnlockedVault> {
        let envelope = self.read_envelope()?;
        let salt = decode(&envelope.salt, "salt")?;
        let nonce = decode(&envelope.nonce, "nonce")?;
        let ciphertext = decode(&envelope.ciphertext, "ciphertext")?;
        self.open_with_key_material(key, salt, &nonce, &ciphertext)
    }

    fn read_envelope(&self) -> Result<VaultEnvelope> {
        read_envelope_from_path(&self.path)
    }

    fn open_with_key_material(
        &self,
        key: VaultKey,
        salt: Vec<u8>,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<UnlockedVault> {
        let nonce_array: [u8; 24] = nonce.try_into().context("invalid vault nonce length")?;
        let plaintext = decrypt_json(&key, nonce, ciphertext)?;
        let data: VaultData =
            serde_json::from_slice(&plaintext).context("failed to parse decrypted vault")?;
        Ok(UnlockedVault {
            store: self.clone(),
            data,
            key,
            salt,
            last_saved_nonce: Cell::new(Some(nonce_array)),
            write_uncertain: Cell::new(false),
        })
    }
}

impl Clone for VaultStore {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
        }
    }
}

impl UnlockedVault {
    pub fn data(&self) -> &VaultData {
        &self.data
    }

    pub fn active_group(&self) -> &str {
        &self.data.active_group
    }

    pub fn key(&self) -> &VaultKey {
        &self.key
    }

    fn persist_or_restore(&mut self, previous: VaultData) -> Result<()> {
        if let Err(error) = self.save() {
            self.data = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        if self.write_uncertain.get() {
            return Err(anyhow!(
                "vault write outcome uncertain; unlock again before saving"
            ));
        }
        ensure_parent_dir(&self.store.path, "failed to create config directory")?;
        // The desktop and MCP server may hold independent snapshots. Keep the
        // version check and atomic replacement under one cross-process lock.
        let lock_path = self.store.path.with_extension("lock");
        let mut lock_options = OpenOptions::new();
        lock_options.read(true).write(true).create(true);
        #[cfg(unix)]
        lock_options.mode(0o600);
        let lock = lock_options
            .open(&lock_path)
            .context("failed to open vault lock")?;
        set_private_file_permissions(&lock_path)?;
        lock.lock().context("failed to lock vault")?;
        let disk_nonce = if self.store.exists() {
            let nonce = decode(&self.store.read_envelope()?.nonce, "nonce")?;
            Some(
                nonce
                    .try_into()
                    .map_err(|_| anyhow!("invalid vault nonce length"))?,
            )
        } else {
            None
        };
        if disk_nonce != self.last_saved_nonce.get() {
            return Err(anyhow!(
                "vault changed on disk; log out and unlock again before saving"
            ));
        }
        let envelope = encrypted_envelope(&self.data, &self.key, &self.salt)?;
        let content =
            serde_json::to_string_pretty(&envelope).context("failed to encode vault envelope")?;
        let temp_path = self
            .store
            .path
            .with_extension(format!("{}.tmp", api_keys::new_id()));
        let write_result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut temp = options
                .open(&temp_path)
                .context("failed to create temporary vault")?;
            set_private_file_permissions(&temp_path)?;
            temp.write_all(content.as_bytes())
                .context("failed to write encrypted vault")?;
            temp.sync_all().context("failed to sync encrypted vault")?;
            fs::rename(&temp_path, &self.store.path).context("failed to replace encrypted vault")
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result?;
        let nonce = decode(&envelope.nonce, "nonce")?;
        self.last_saved_nonce.set(Some(
            nonce
                .try_into()
                .map_err(|_| anyhow!("invalid vault nonce length"))?,
        ));
        #[cfg(unix)]
        if let Err(error) =
            fs::File::open(self.store.path.parent().unwrap()).and_then(|parent| parent.sync_all())
        {
            self.write_uncertain.set(true);
            return Err(error)
                .context("failed to sync vault directory; unlock again before saving");
        }
        Ok(())
    }

    pub fn export_to_path(&self, path: &Path, password: &str) -> Result<()> {
        if password.is_empty() {
            return Err(anyhow!("password cannot be empty"));
        }

        ensure_parent_dir(path, "failed to create export directory")?;
        let salt = random_salt();
        let key = derive_key(password, &salt)?;
        let envelope = encrypted_envelope(&self.data, &key, &salt)?;
        let content = serde_json::to_string_pretty(&envelope).context("failed to encode export")?;
        fs::write(path, content)
            .with_context(|| format!("failed to write export {}", path.display()))?;
        set_private_file_permissions(path)?;
        Ok(())
    }

    pub fn import_from_path(&mut self, path: &Path, password: &str) -> Result<()> {
        if password.is_empty() {
            return Err(anyhow!("password cannot be empty"));
        }

        let data = read_vault_data_from_path(path, password)?;
        validate_imported_data(&data)?;
        let previous_data = self.data.clone();

        self.data = data;
        if let Err(err) = self.save() {
            self.data = previous_data;
            return Err(err);
        }
        Ok(())
    }

    pub fn change_password(&mut self, password: &str) -> Result<()> {
        let salt = random_salt();
        let key = derive_key(password, &salt)?;
        let previous_key = self.key;
        let previous_salt = self.salt.clone();

        self.key = key;
        self.salt = salt.to_vec();
        if let Err(err) = self.save() {
            self.key = previous_key;
            self.salt = previous_salt;
            return Err(err);
        }
        Ok(())
    }

    pub fn switch_group(&mut self, group: &str) -> Result<()> {
        if !self.data.groups.contains_key(group) {
            return Err(anyhow!("group '{group}' does not exist"));
        }
        let previous = self.data.clone();
        self.data.active_group = group.to_string();
        self.persist_or_restore(previous)
    }

    pub fn create_group(&mut self, group: &str) -> Result<()> {
        validate_name(group)?;
        if self.data.groups.contains_key(group) {
            return Err(anyhow!("group '{group}' already exists"));
        }
        let previous = self.data.clone();
        self.data.groups.insert(group.to_string(), Group::default());
        self.data.active_group = group.to_string();
        self.persist_or_restore(previous)
    }

    pub fn rename_group(&mut self, old_group: &str, new_group: &str) -> Result<()> {
        validate_name(new_group)?;
        if !self.data.groups.contains_key(old_group) {
            return Err(anyhow!("group '{old_group}' does not exist"));
        }
        if old_group == new_group {
            return Ok(());
        }
        if self.data.groups.contains_key(new_group) {
            return Err(anyhow!("group '{new_group}' already exists"));
        }

        let previous = self.data.clone();
        let group = self
            .data
            .groups
            .remove(old_group)
            .ok_or_else(|| anyhow!("group '{old_group}' does not exist"))?;
        self.data.groups.insert(new_group.to_string(), group);
        if self.data.active_group == old_group {
            self.data.active_group = new_group.to_string();
        }
        self.revoke_group_scope(old_group);
        self.persist_or_restore(previous)
    }

    pub fn delete_group(&mut self, group: &str) -> Result<()> {
        if self.data.groups.len() == 1 {
            return Err(anyhow!("cannot delete the last group"));
        }
        if !self.data.groups.contains_key(group) {
            return Err(anyhow!("group '{group}' does not exist"));
        }
        let previous = self.data.clone();
        self.data.groups.remove(group);
        if self.data.active_group == group {
            self.data.active_group = self
                .data
                .groups
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| DEFAULT_GROUP.to_string());
        }
        self.revoke_group_scope(group);
        self.persist_or_restore(previous)
    }

    fn revoke_group_scope(&mut self, group: &str) {
        for key in self.data.api_keys.values_mut() {
            key.permissions.remove(group);
        }
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        validate_name(key)?;
        let previous = self.data.clone();
        self.active_group_mut()?
            .secrets
            .insert(key.to_string(), value.to_string());
        self.persist_or_restore(previous)
    }

    pub fn rename_secret(&mut self, old_key: &str, new_key: &str, value: &str) -> Result<()> {
        validate_name(new_key)?;
        if old_key != new_key && self.active_group_ref()?.secrets.contains_key(new_key) {
            return Err(anyhow!("secret '{new_key}' already exists"));
        }

        let previous = self.data.clone();
        let group = self.active_group_mut()?;
        if old_key != new_key {
            group
                .secrets
                .remove(old_key)
                .ok_or_else(|| anyhow!("secret '{old_key}' does not exist"))?;
        }
        group.secrets.insert(new_key.to_string(), value.to_string());
        self.persist_or_restore(previous)
    }

    pub fn get(&self, key: &str) -> Result<Option<&String>> {
        Ok(self.active_group_ref()?.secrets.get(key))
    }

    pub fn delete(&mut self, key: &str) -> Result<bool> {
        let previous = self.data.clone();
        let removed = self.active_group_mut()?.secrets.remove(key).is_some();
        if removed {
            self.persist_or_restore(previous)?;
        }
        Ok(removed)
    }

    pub fn get_in_group(&self, group: &str, key: &str) -> Result<Option<&str>> {
        Ok(self
            .data
            .groups
            .get(group)
            .ok_or_else(|| anyhow!("group '{group}' does not exist"))?
            .secrets
            .get(key)
            .map(String::as_str))
    }

    pub fn set_in_group(&mut self, group: &str, key: &str, value: &str) -> Result<()> {
        validate_name(key)?;
        let previous = self.data.clone();
        self.data
            .groups
            .get_mut(group)
            .ok_or_else(|| anyhow!("group '{group}' does not exist"))?
            .secrets
            .insert(key.to_string(), value.to_string());
        self.persist_or_restore(previous)
    }

    pub fn delete_in_group(&mut self, group: &str, key: &str) -> Result<bool> {
        let previous = self.data.clone();
        let removed = self
            .data
            .groups
            .get_mut(group)
            .ok_or_else(|| anyhow!("group '{group}' does not exist"))?
            .secrets
            .remove(key)
            .is_some();
        if removed {
            self.persist_or_restore(previous)?;
        }
        Ok(removed)
    }

    pub fn create_api_key(
        &mut self,
        name: &str,
        permissions: BTreeMap<String, Access>,
        expires_at: Option<i64>,
    ) -> Result<(String, String)> {
        api_keys::validate(name, &permissions, expires_at, &self.data)?;
        let id = api_keys::new_id();
        let record = ApiKey {
            id: id.clone(),
            name: name.trim().to_string(),
            permissions,
            expires_at,
        };
        let secret = self
            .data
            .api_signing_key
            .clone()
            .unwrap_or_else(api_keys::new_secret);
        let token = api_keys::issue(&record, &secret)?;
        let previous_secret = self.data.api_signing_key.replace(secret);
        self.data.api_keys.insert(id.clone(), record);
        if let Err(err) = self.save() {
            self.data.api_keys.remove(&id);
            self.data.api_signing_key = previous_secret;
            return Err(err);
        }
        Ok((id, token))
    }

    pub fn edit_api_key(
        &mut self,
        old_id: &str,
        name: &str,
        permissions: BTreeMap<String, Access>,
        expires_at: Option<i64>,
    ) -> Result<(String, String)> {
        api_keys::validate(name, &permissions, expires_at, &self.data)?;
        if !self.data.api_keys.contains_key(old_id) {
            return Err(anyhow!("API key not found"));
        }
        let id = api_keys::new_id();
        let record = ApiKey {
            id: id.clone(),
            name: name.trim().to_string(),
            permissions,
            expires_at,
        };
        let token = api_keys::issue(
            &record,
            self.data
                .api_signing_key
                .as_deref()
                .ok_or_else(|| anyhow!("API signing key missing"))?,
        )?;
        let previous = self.data.api_keys.remove(old_id).unwrap();
        self.data.api_keys.insert(id.clone(), record);
        if let Err(err) = self.save() {
            self.data.api_keys.remove(&id);
            self.data.api_keys.insert(old_id.to_string(), previous);
            return Err(err);
        }
        Ok((id, token))
    }

    pub fn delete_api_key(&mut self, id: &str) -> Result<()> {
        let previous = self
            .data
            .api_keys
            .remove(id)
            .ok_or_else(|| anyhow!("API key not found"))?;
        if let Err(err) = self.save() {
            self.data.api_keys.insert(id.to_string(), previous);
            return Err(err);
        }
        Ok(())
    }

    pub fn active_group_ref(&self) -> Result<&Group> {
        self.data
            .groups
            .get(&self.data.active_group)
            .ok_or_else(|| anyhow!("active group '{}' is missing", self.data.active_group))
    }

    fn active_group_mut(&mut self) -> Result<&mut Group> {
        self.data
            .groups
            .get_mut(&self.data.active_group)
            .ok_or_else(|| anyhow!("active group '{}' is missing", self.data.active_group))
    }
}

fn encrypted_envelope(data: &VaultData, key: &VaultKey, salt: &[u8]) -> Result<VaultEnvelope> {
    let plaintext = serde_json::to_vec_pretty(data).context("failed to encode vault")?;
    let (nonce, ciphertext) = encrypt_json(key, &plaintext)?;
    Ok(VaultEnvelope {
        version: ENVELOPE_VERSION,
        kdf: KDF_NAME.to_string(),
        cipher: CIPHER_NAME.to_string(),
        salt: encode(salt),
        nonce: encode(&nonce),
        ciphertext: encode(&ciphertext),
    })
}

fn read_vault_data_from_path(path: &Path, password: &str) -> Result<VaultData> {
    let envelope = read_envelope_from_path(path)?;
    let salt = decode(&envelope.salt, "salt")?;
    let nonce = decode(&envelope.nonce, "nonce")?;
    let ciphertext = decode(&envelope.ciphertext, "ciphertext")?;
    let key = derive_key(password, &salt)?;
    let plaintext = decrypt_json(&key, &nonce, &ciphertext)?;
    serde_json::from_slice(&plaintext).context("failed to parse decrypted vault")
}

fn read_envelope_from_path(path: &Path) -> Result<VaultEnvelope> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read encrypted vault {}", path.display()))?;
    let envelope: VaultEnvelope =
        serde_json::from_str(&content).context("failed to parse encrypted vault envelope")?;

    if envelope.version != ENVELOPE_VERSION {
        return Err(anyhow!("unsupported vault version {}", envelope.version));
    }
    if envelope.kdf != KDF_NAME {
        return Err(anyhow!("unsupported vault KDF {}", envelope.kdf));
    }
    if envelope.cipher != CIPHER_NAME {
        return Err(anyhow!("unsupported vault cipher {}", envelope.cipher));
    }

    Ok(envelope)
}

fn validate_imported_data(data: &VaultData) -> Result<()> {
    if data.groups.is_empty() {
        return Err(anyhow!("imported vault contains no groups"));
    }
    if !data.groups.contains_key(&data.active_group) {
        return Err(anyhow!(
            "imported vault active group '{}' is missing",
            data.active_group
        ));
    }

    for (group_name, group) in &data.groups {
        validate_name(group_name)
            .with_context(|| format!("invalid imported group name '{group_name}'"))?;
        for key in group.secrets.keys() {
            validate_name(key).with_context(|| format!("invalid imported secret name '{key}'"))?;
        }
    }

    Ok(())
}

fn ensure_parent_dir(path: &Path, context: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).context(context.to_string())?;
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("name cannot be empty"));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(anyhow!("name cannot contain path separators"));
    }
    Ok(())
}

#[cfg(unix)]
pub fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .with_context(|| format!("failed to read permissions for {}", path.display()))?
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to set private permissions on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_group_name_reused_after_rename_does_not_restore_key_access() {
        let store = VaultStore::for_test(
            std::env::temp_dir().join(format!("ks-rename-test-{}.json", api_keys::new_id())),
        );
        let mut vault = store.create("test-only-password").unwrap();
        vault.create_group("work").unwrap();
        let (_, token) = vault
            .create_api_key("client", [("work".into(), Access::ReadOnly)].into(), None)
            .unwrap();
        vault.rename_group("work", "renamed").unwrap();
        vault.create_group("work").unwrap();
        assert!(api_keys::authenticate(&token, &vault).is_err());
        fs::remove_file(&store.path).unwrap();
    }

    #[test]
    fn old_group_name_reused_after_delete_does_not_restore_key_access() {
        let store = VaultStore::for_test(
            std::env::temp_dir().join(format!("ks-delete-test-{}.json", api_keys::new_id())),
        );
        let mut vault = store.create("test-only-password").unwrap();
        vault.create_group("work").unwrap();
        let (_, token) = vault
            .create_api_key("client", [("work".into(), Access::ReadOnly)].into(), None)
            .unwrap();
        vault.delete_group("work").unwrap();
        vault.create_group("work").unwrap();
        assert!(api_keys::authenticate(&token, &vault).is_err());
        fs::remove_file(&store.path).unwrap();
    }

    #[test]
    fn stale_vault_write_cannot_restore_revoked_key_or_erase_new_secrets() {
        let store = VaultStore::for_test(
            std::env::temp_dir().join(format!("ks-race-test-{}.json", api_keys::new_id())),
        );
        let mut desktop = store.create("test-only-password").unwrap();
        let (id, token) = desktop
            .create_api_key(
                "client",
                [("default".into(), Access::ReadWrite)].into(),
                None,
            )
            .unwrap();
        let mut stale_server = store.unlock("test-only-password").unwrap();
        desktop.delete_api_key(&id).unwrap();
        assert!(stale_server
            .set_in_group("default", "NEW", "value")
            .is_err());
        let reopened = store.unlock("test-only-password").unwrap();
        assert!(api_keys::authenticate(&token, &reopened).is_err());
        assert!(reopened.get_in_group("default", "NEW").unwrap().is_none());

        let mut stale_desktop = store.unlock("test-only-password").unwrap();
        let mut server = store.unlock("test-only-password").unwrap();
        server.set_in_group("default", "SERVER", "value").unwrap();
        assert!(stale_desktop.set("DESKTOP", "old").is_err());
        let reopened = store.unlock("test-only-password").unwrap();
        assert_eq!(
            reopened.get_in_group("default", "SERVER").unwrap(),
            Some("value")
        );
        fs::remove_file(&store.path).unwrap();
    }

    #[test]
    fn simultaneous_writers_cannot_overwrite_each_other() {
        let store = VaultStore::for_test(
            std::env::temp_dir().join(format!("ks-parallel-test-{}.json", api_keys::new_id())),
        );
        store.create("test-only-password").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = ["one", "two"]
            .into_iter()
            .map(|key| {
                let mut vault = store.unlock("test-only-password").unwrap();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    vault.set(key, "value")
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let vault = store.unlock("test-only-password").unwrap();
        assert_eq!(vault.active_group_ref().unwrap().secrets.len(), 1);
        fs::remove_file(&store.path).unwrap();
    }

    #[test]
    fn failed_group_and_secret_saves_restore_in_memory_state() {
        let store = VaultStore::for_test(
            std::env::temp_dir().join(format!("ks-rollback-test-{}.json", api_keys::new_id())),
        );
        let mut current = store.create("test-only-password").unwrap();
        current.create_group("work").unwrap();
        let (_, token) = current
            .create_api_key("client", [("work".into(), Access::ReadOnly)].into(), None)
            .unwrap();
        let mut stale = store.unlock("test-only-password").unwrap();
        current.set_in_group("work", "FRESH", "value").unwrap();
        assert!(stale.rename_group("work", "renamed").is_err());
        assert!(stale.data().groups.contains_key("work"));
        assert_eq!(
            stale.data().api_keys.values().next().unwrap().permissions["work"],
            Access::ReadOnly
        );
        assert!(stale.delete_group("work").is_err());
        assert!(stale.data().groups.contains_key("work"));
        assert!(stale.set_in_group("default", "STALE", "value").is_err());
        assert!(stale.get_in_group("default", "STALE").unwrap().is_none());
        let reopened = store.unlock("test-only-password").unwrap();
        assert!(api_keys::authenticate(&token, &reopened).is_ok());
        assert_eq!(
            reopened.get_in_group("work", "FRESH").unwrap(),
            Some("value")
        );
        fs::remove_file(&store.path).unwrap();
    }

    #[test]
    fn older_vaults_without_api_key_fields_remain_readable() {
        let old = r#"{"active_group":"default","groups":{"default":{"secrets":{}}}}"#;
        let data: VaultData = serde_json::from_str(old).unwrap();
        assert!(data.api_keys.is_empty());
        assert!(data.api_signing_key.is_none());
    }

    #[test]
    fn api_key_creation_edit_and_deletion_enforce_current_permissions() {
        let store = VaultStore {
            path: std::env::temp_dir().join(format!("ks-api-test-{}.json", api_keys::new_id())),
        };
        let mut vault = store.create("test-only-password").unwrap();
        let read = [("default".to_string(), Access::ReadOnly)].into();
        let (id, token) = vault.create_api_key("client", read, None).unwrap();
        assert_eq!(
            api_keys::authenticate(&token, &vault).unwrap().permissions["default"],
            Access::ReadOnly
        );

        let write = [("default".to_string(), Access::ReadWrite)].into();
        let (new_id, rotated) = vault.edit_api_key(&id, "client", write, None).unwrap();
        assert_ne!(id, new_id);
        assert!(api_keys::authenticate(&token, &vault).is_err());
        assert_eq!(
            api_keys::authenticate(&rotated, &vault)
                .unwrap()
                .permissions["default"],
            Access::ReadWrite
        );

        vault.delete_api_key(&new_id).unwrap();
        assert!(api_keys::authenticate(&rotated, &vault).is_err());
        fs::remove_file(&store.path).unwrap();
    }

    #[test]
    fn scoped_operations_do_not_switch_active_group() {
        let store = VaultStore {
            path: std::env::temp_dir().join(format!("ks-scoped-test-{}.json", api_keys::new_id())),
        };
        let mut vault = store.create("test-only-password").unwrap();
        vault.create_group("work").unwrap();
        vault.switch_group("default").unwrap();
        vault.set_in_group("work", "KEY", "value").unwrap();
        assert_eq!(vault.get_in_group("work", "KEY").unwrap(), Some("value"));
        assert_eq!(vault.active_group(), "default");
        assert!(vault.delete_in_group("work", "KEY").unwrap());
        assert!(vault.get_in_group("work", "KEY").unwrap().is_none());
        fs::remove_file(&store.path).unwrap();
    }
}
