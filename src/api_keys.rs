use crate::crypto::{decode, encode};
use crate::storage::{UnlockedVault, VaultData};
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use jsonwebtoken::{
    decode as jwt_decode, encode as jwt_encode, Algorithm, DecodingKey, EncodingKey, Header,
    Validation,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub permissions: BTreeMap<String, Access>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    jti: String,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    permissions: BTreeMap<String, Access>,
}

pub fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs() as i64)
}

pub fn new_secret() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    encode(&bytes)
}

pub fn new_id() -> String {
    let mut bytes = [0_u8; 24];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn validate(
    name: &str,
    permissions: &BTreeMap<String, Access>,
    expires_at: Option<i64>,
    data: &VaultData,
) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("API key name cannot be empty"));
    }
    if permissions.is_empty() {
        return Err(anyhow!("select at least one group"));
    }
    for group in permissions.keys() {
        if !data.groups.contains_key(group) {
            return Err(anyhow!("group '{group}' does not exist"));
        }
    }
    if let Some(expiry) = expires_at {
        if expiry <= now()? {
            return Err(anyhow!("expiry must be in the future"));
        }
    }
    Ok(())
}

pub fn issue(record: &ApiKey, secret: &str) -> Result<String> {
    let key = decode(secret, "API signing key")?;
    let claims = Claims {
        iss: "ks-mcp".into(),
        jti: record.id.clone(),
        iat: now()? as u64,
        exp: record.expires_at,
        permissions: record.permissions.clone(),
    };
    jwt_encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&key),
    )
    .context("failed to issue API key")
}

pub fn authenticate_data(token: &str, data: &VaultData) -> Result<ApiKey> {
    let secret = data
        .api_signing_key
        .as_deref()
        .ok_or_else(|| anyhow!("invalid API key"))?;
    let key = decode(secret, "API signing key")?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let claims = jwt_decode::<Claims>(token, &DecodingKey::from_secret(&key), &validation)
        .map_err(|_| anyhow!("invalid API key"))?
        .claims;
    if claims.iss != "ks-mcp" || claims.iat > now()? as u64 {
        return Err(anyhow!("invalid API key"));
    }
    let record = data
        .api_keys
        .get(&claims.jti)
        .ok_or_else(|| anyhow!("invalid API key"))?;
    if record.permissions != claims.permissions || record.expires_at != claims.exp {
        return Err(anyhow!("invalid API key"));
    }
    if let Some(expiry) = claims.exp {
        if expiry <= now()? {
            return Err(anyhow!("API key expired"));
        }
    }
    Ok(record.clone())
}

pub fn authenticate(token: &str, vault: &UnlockedVault) -> Result<ApiKey> {
    authenticate_data(token, vault.data())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encode;

    fn fixture() -> (VaultData, ApiKey) {
        let mut data = VaultData {
            api_signing_key: Some(encode(&[9; 32])),
            ..VaultData::default()
        };
        let record = ApiKey {
            id: "test-id".into(),
            name: "automation".into(),
            permissions: [("default".into(), Access::ReadOnly)].into(),
            expires_at: None,
        };
        data.api_keys.insert(record.id.clone(), record.clone());
        (data, record)
    }

    #[test]
    fn signed_key_authenticates_and_restricts_access() {
        let (data, record) = fixture();
        let token = issue(&record, data.api_signing_key.as_deref().unwrap()).unwrap();
        let validated = authenticate_data(&token, &data).unwrap();
        assert_eq!(validated.id, record.id);
        assert_eq!(validated.permissions["default"], Access::ReadOnly);
    }

    #[test]
    fn deleted_or_edited_key_is_immediately_rejected() {
        let (mut data, record) = fixture();
        let token = issue(&record, data.api_signing_key.as_deref().unwrap()).unwrap();
        data.api_keys.remove(&record.id);
        assert!(authenticate_data(&token, &data).is_err());
        data.api_keys.insert(record.id.clone(), record);
        data.api_keys
            .get_mut("test-id")
            .unwrap()
            .permissions
            .insert("default".into(), Access::ReadWrite);
        assert!(authenticate_data(&token, &data).is_err());
    }

    #[test]
    fn expired_and_tampered_keys_are_rejected() {
        let (mut data, record) = fixture();
        let token = issue(&record, data.api_signing_key.as_deref().unwrap()).unwrap();
        data.api_keys.get_mut("test-id").unwrap().expires_at = Some(0);
        assert!(authenticate_data(&token, &data).is_err());
        let expired = issue(
            data.api_keys.get("test-id").unwrap(),
            data.api_signing_key.as_deref().unwrap(),
        )
        .unwrap();
        assert!(authenticate_data(&expired, &data).is_err());
        data.api_keys.get_mut("test-id").unwrap().expires_at = None;
        assert!(authenticate_data(&format!("{token}x"), &data).is_err());
    }
}
