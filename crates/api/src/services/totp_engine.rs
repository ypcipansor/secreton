//! TOTP Secret Engine Service
//!
//! Manages TOTP keys for external services and generates codes.

use anyhow::{Result, anyhow};
use std::sync::Arc;

use crate::services::crypto::CryptoService;
use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;

const TOTP_ENGINE_PREFIX: &str = "sys/totp/";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TotpKeyMetadata {
    pub name: String,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
    pub algorithm: String,
    pub digits: usize,
    pub period: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub struct TotpEngineService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
}

impl TotpEngineService {
    pub fn new(storage: Arc<dyn StorageBackend + Send + Sync>, crypto: Arc<CryptoService>) -> Self {
        Self { storage, crypto }
    }

    fn get_user_prefix(&self, user_id: &str) -> String {
        format!("{}{}/", TOTP_ENGINE_PREFIX, user_id)
    }

    pub async fn create_key(
        &self,
        user_id: &str,
        name: &str,
        secret_b32: &str,
        issuer: Option<String>,
        account_name: Option<String>,
    ) -> Result<()> {
        let owner_id = Uuid::parse_str(user_id).map_err(|e| anyhow!("Invalid user ID: {}", e))?;

        // Validate secret by attempting to decode it
        let _ = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
            .ok_or_else(|| anyhow!("Invalid base32 secret"))?;

        let metadata = TotpKeyMetadata {
            name: name.to_string(),
            issuer,
            account_name,
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
            created_at: chrono::Utc::now(),
        };

        // We store the secret separately or in the same entry?
        // Let's store in one entry for simplicity, encrypted.
        let data = serde_json::json!({
            "metadata": metadata,
            "secret": secret_b32,
        });

        let bytes = serde_json::to_vec(&data)?;
        let encrypted = self.crypto.encrypt_data(&bytes).await?;

        let path = format!("{}{}", self.get_user_prefix(user_id), name);
        let entry = SecretEntry::new(
            path,
            encrypted,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            owner_id,
        );

        self.storage.store(&entry).await?;
        Ok(())
    }

    pub async fn list_keys(&self, user_id: &str) -> Result<Vec<String>> {
        let prefix = self.get_user_prefix(user_id);
        let query = secreton_storage::QueryParams {
            path_prefix: Some(prefix.clone()),
            ..Default::default()
        };

        let entries = self.storage.list(&query).await?;
        let mut keys = Vec::new();
        for entry in entries {
            if let Some(name) = entry.path.strip_prefix(&prefix) {
                keys.push(name.to_string());
            }
        }
        Ok(keys)
    }

    pub async fn generate_code(&self, user_id: &str, name: &str) -> Result<String> {
        let path = format!("{}{}", self.get_user_prefix(user_id), name);
        let entry = self.storage.get_by_path(&path).await?
            .ok_or_else(|| anyhow!("Key not found"))?;

        let decrypted = self.crypto.decrypt(&entry.encrypted_data).await?;
        let data: serde_json::Value = serde_json::from_slice(&decrypted)?;

        let secret_b32 = data["secret"].as_str().ok_or_else(|| anyhow!("Missing secret"))?;
        let metadata_val = &data["metadata"];

        let algorithm = match metadata_val["algorithm"].as_str().unwrap_or("SHA1") {
            "SHA256" => Algorithm::SHA256,
            "SHA512" => Algorithm::SHA512,
            _ => Algorithm::SHA1,
        };

        let digits = metadata_val["digits"].as_u64().unwrap_or(6) as usize;
        let period = metadata_val["period"].as_u64().unwrap_or(30);

        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
            .ok_or_else(|| anyhow!("Invalid stored secret"))?;

        let totp = TOTP::new(
            algorithm,
            digits,
            1,
            period,
            secret_bytes,
            None,
            "".to_string(),
        ).map_err(|e| anyhow!("TOTP error: {}", e))?;

        Ok(totp.generate_current().map_err(|e| anyhow!("Failed to generate code: {}", e))?)
    }

    pub async fn delete_key(&self, user_id: &str, name: &str) -> Result<()> {
        let path = format!("{}{}", self.get_user_prefix(user_id), name);
        self.storage.delete_by_path(&path).await?;
        Ok(())
    }
}
