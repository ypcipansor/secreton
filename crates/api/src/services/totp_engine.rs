//! TOTP Secret Engine Service
//!
//! Manages TOTP keys for external services and generates codes.

use anyhow::Result;
use std::sync::Arc;

use crate::services::crypto::CryptoService;
use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;

/// Categorised service error that handlers can map to the appropriate HTTP status.
#[derive(Debug)]
pub enum TotpServiceError {
    /// The requested key was not found (→ 404).
    NotFound(String),
    /// A client-supplied value is invalid (→ 400).
    BadRequest(String),
    /// Any other unexpected failure (→ 500).
    Internal(String),
}

impl std::fmt::Display for TotpServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "{}", msg),
            Self::BadRequest(msg) => write!(f, "{}", msg),
            Self::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<anyhow::Error> for TotpServiceError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

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

    /// Validate that a user_id is safe for use in storage paths.
    ///
    /// Defence-in-depth: user IDs are expected to be UUIDs (hex + hyphens),
    /// but if a non-UUID auth backend is ever integrated, a malicious user_id
    /// containing `../` could escape the TOTP namespace.
    fn validate_user_id(user_id: &str) -> std::result::Result<(), TotpServiceError> {
        if user_id.is_empty() {
            return Err(TotpServiceError::BadRequest(
                "User ID must not be empty".to_string(),
            ));
        }
        if user_id.contains('/') || user_id.contains('\\') || user_id.contains("..") {
            return Err(TotpServiceError::BadRequest(
                "User ID must not contain '/', '\\', or '..'".to_string(),
            ));
        }
        if user_id.chars().any(|c| c.is_control()) {
            return Err(TotpServiceError::BadRequest(
                "User ID must not contain control characters".to_string(),
            ));
        }
        Ok(())
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
    ) -> std::result::Result<(), TotpServiceError> {
        Self::validate_user_id(user_id)?;

        // Try to parse user_id as UUID for the owner field; fall back to a
        // deterministic UUID-v5 derived from the user_id string so that
        // non-UUID user IDs still work.
        let owner_id = Uuid::parse_str(user_id)
            .unwrap_or_else(|_| Uuid::new_v5(&Uuid::NAMESPACE_OID, user_id.as_bytes()));

        // Validate secret by attempting to decode it and checking the minimum
        // length required by the TOTP algorithm.  `totp-rs` v5.6.0 enforces a
        // minimum of 16 bytes for SHA1, 32 for SHA256, and 64 for SHA512.
        // We default to SHA1, so enforce 16 bytes here.  Rejecting at creation
        // time avoids a confusing Internal error at code-generation time.
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
            .ok_or_else(|| TotpServiceError::BadRequest("Invalid base32 secret".to_string()))?;

        const MIN_SECRET_BYTES: usize = 16; // SHA1 HMAC minimum (RFC 4226)
        if secret_bytes.len() < MIN_SECRET_BYTES {
            return Err(TotpServiceError::BadRequest(format!(
                "Secret too short: decoded to {} bytes, minimum is {} bytes. \
                 Provide a base32-encoded secret of at least {} characters.",
                secret_bytes.len(),
                MIN_SECRET_BYTES,
                // ceil(16 * 8 / 5) = 26 base32 characters (no padding)
                (MIN_SECRET_BYTES * 8 + 4) / 5,
            )));
        }

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

        let bytes = serde_json::to_vec(&data)
            .map_err(|e| TotpServiceError::Internal(e.to_string()))?;
        let encrypted = self.crypto.encrypt_data(&bytes).await
            .map_err(|e| TotpServiceError::Internal(e.to_string()))?;

        let path = format!("{}{}", self.get_user_prefix(user_id), name);
        let entry = SecretEntry::new(
            path,
            encrypted,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            owner_id,
        );

        self.storage.store(&entry).await
            .map_err(|e| TotpServiceError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn list_keys(&self, user_id: &str) -> Result<Vec<String>> {
        Self::validate_user_id(user_id)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
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

    pub async fn generate_code(
        &self,
        user_id: &str,
        name: &str,
    ) -> std::result::Result<String, TotpServiceError> {
        Self::validate_user_id(user_id)?;
        let path = format!("{}{}", self.get_user_prefix(user_id), name);
        let entry = self.storage.get_by_path(&path).await
            .map_err(|e| TotpServiceError::Internal(e.to_string()))?
            .ok_or_else(|| TotpServiceError::NotFound(format!("Key '{}' not found", name)))?;

        let decrypted = self.crypto.decrypt(&entry.encrypted_data).await
            .map_err(|e| TotpServiceError::Internal(e.to_string()))?;
        let data: serde_json::Value = serde_json::from_slice(&decrypted)
            .map_err(|e| TotpServiceError::Internal(e.to_string()))?;

        let secret_b32 = data["secret"].as_str()
            .ok_or_else(|| TotpServiceError::Internal("Missing secret in stored data".to_string()))?;
        let metadata_val = &data["metadata"];

        let algorithm = match metadata_val["algorithm"].as_str().unwrap_or("SHA1") {
            "SHA256" => Algorithm::SHA256,
            "SHA512" => Algorithm::SHA512,
            _ => Algorithm::SHA1,
        };

        let digits = metadata_val["digits"].as_u64().unwrap_or(6) as usize;
        let period = metadata_val["period"].as_u64().unwrap_or(30);

        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
            .ok_or_else(|| TotpServiceError::Internal("Invalid stored secret".to_string()))?;

        let totp = TOTP::new(
            algorithm,
            digits,
            1,
            period,
            secret_bytes,
            metadata_val["issuer"].as_str().map(|s| s.to_string()),
            metadata_val["account_name"].as_str().unwrap_or("secreton").to_string(),
        ).map_err(|e| TotpServiceError::Internal(format!("TOTP error: {}", e)))?;

        totp.generate_current()
            .map_err(|e| TotpServiceError::Internal(format!("Failed to generate code: {}", e)))
    }

    pub async fn delete_key(&self, user_id: &str, name: &str) -> Result<()> {
        Self::validate_user_id(user_id)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let path = format!("{}{}", self.get_user_prefix(user_id), name);
        self.storage.delete_by_path(&path).await?;
        Ok(())
    }
}
