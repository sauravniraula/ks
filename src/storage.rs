use crate::crypto::{
    decode, decrypt_json, derive_key, encode, encrypt_json, random_salt, VaultKey,
};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
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
}

impl Default for VaultData {
    fn default() -> Self {
        let mut groups = BTreeMap::new();
        groups.insert(DEFAULT_GROUP.to_string(), Group::default());
        Self {
            active_group: DEFAULT_GROUP.to_string(),
            groups,
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
        let plaintext = decrypt_json(&key, nonce, ciphertext)?;
        let data: VaultData =
            serde_json::from_slice(&plaintext).context("failed to parse decrypted vault")?;
        Ok(UnlockedVault {
            store: self.clone(),
            data,
            key,
            salt,
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

    pub fn save(&self) -> Result<()> {
        ensure_parent_dir(&self.store.path, "failed to create config directory")?;

        let envelope = encrypted_envelope(&self.data, &self.key, &self.salt)?;
        let content =
            serde_json::to_string_pretty(&envelope).context("failed to encode vault envelope")?;
        fs::write(&self.store.path, content).context("failed to write encrypted vault")?;
        set_private_file_permissions(&self.store.path)?;
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
        self.data.active_group = group.to_string();
        self.save()
    }

    pub fn create_group(&mut self, group: &str) -> Result<()> {
        validate_name(group)?;
        if self.data.groups.contains_key(group) {
            return Err(anyhow!("group '{group}' already exists"));
        }
        self.data.groups.insert(group.to_string(), Group::default());
        self.data.active_group = group.to_string();
        self.save()
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

        let group = self
            .data
            .groups
            .remove(old_group)
            .ok_or_else(|| anyhow!("group '{old_group}' does not exist"))?;
        self.data.groups.insert(new_group.to_string(), group);
        if self.data.active_group == old_group {
            self.data.active_group = new_group.to_string();
        }
        self.save()
    }

    pub fn delete_group(&mut self, group: &str) -> Result<()> {
        if self.data.groups.len() == 1 {
            return Err(anyhow!("cannot delete the last group"));
        }
        if self.data.groups.remove(group).is_none() {
            return Err(anyhow!("group '{group}' does not exist"));
        }
        if self.data.active_group == group {
            self.data.active_group = self
                .data
                .groups
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| DEFAULT_GROUP.to_string());
        }
        self.save()
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        validate_name(key)?;
        self.active_group_mut()?
            .secrets
            .insert(key.to_string(), value.to_string());
        self.save()
    }

    pub fn rename_secret(&mut self, old_key: &str, new_key: &str, value: &str) -> Result<()> {
        validate_name(new_key)?;
        if old_key != new_key && self.active_group_ref()?.secrets.contains_key(new_key) {
            return Err(anyhow!("secret '{new_key}' already exists"));
        }

        let group = self.active_group_mut()?;
        if old_key != new_key {
            group
                .secrets
                .remove(old_key)
                .ok_or_else(|| anyhow!("secret '{old_key}' does not exist"))?;
        }
        group.secrets.insert(new_key.to_string(), value.to_string());
        self.save()
    }

    pub fn get(&self, key: &str) -> Result<Option<&String>> {
        Ok(self.active_group_ref()?.secrets.get(key))
    }

    pub fn delete(&mut self, key: &str) -> Result<bool> {
        let removed = self.active_group_mut()?.secrets.remove(key).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
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
