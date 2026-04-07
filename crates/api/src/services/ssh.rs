//! Persistent SSH Service
//!
//! Handles persistence of SSH Certificate Authority (CA) state using the StorageBackend
//! and CryptoService. Wraps the in-memory SshEngine.

use anyhow::Result;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::services::crypto::CryptoService;
use secreton_secrets::{SecretError, SshConfig, SshEngine, SecretEngine};
use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend};
use chrono::Utc;

/// Maximum lease TTL for SSH certificates (30 days in seconds).
///
/// Shared between the service configuration and the handler TTL clamping logic
/// to avoid silent drift when one side is updated without the other.
pub const SSH_MAX_LEASE_TTL: u64 = 86400 * 30;

/// Categorised service error that handlers can map to the appropriate HTTP status.
#[derive(Debug)]
pub enum SshServiceError {
    /// The requested resource was not found (→ 404).
    NotFound(String),
    /// A conflicting state prevents the operation (→ 409).
    Conflict(String),
    /// A client-supplied value is invalid (→ 400).
    BadRequest(String),
    /// Any other unexpected failure (→ 500).
    Internal(String),
}

impl std::fmt::Display for SshServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "{}", msg),
            Self::Conflict(msg) => write!(f, "{}", msg),
            Self::BadRequest(msg) => write!(f, "{}", msg),
            Self::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SshServiceError {}

impl From<anyhow::Error> for SshServiceError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<serde_json::Error> for SshServiceError {
    fn from(err: serde_json::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

const SSH_CA_STORAGE_PATH: &str = "sys/ssh/ca";

pub struct SshPersistentService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    engine: Arc<RwLock<SshEngine>>,
    initialized: std::sync::atomic::AtomicBool,
}

impl SshPersistentService {
    pub fn new(storage: Arc<dyn StorageBackend + Send + Sync>, crypto: Arc<CryptoService>) -> Self {
        let config = SshConfig {
            default_lease_ttl: 3600,
            max_lease_ttl: SSH_MAX_LEASE_TTL,
            allowed_users: vec![],
            allowed_extensions: vec![],
            ca_private_key: None,
            ca_public_key: None,
        };
        let engine = SshEngine::new(config);

        Self {
            storage,
            crypto,
            engine: Arc::new(RwLock::new(engine)),
            initialized: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Ensure the service is initialized by loading CA from storage
    pub async fn ensure_initialized(&self) -> Result<()> {
        if self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }

        let maybe_ca = if let Some(entry) = self.storage.get_by_path(SSH_CA_STORAGE_PATH).await? {
            let mut decrypted_data = self.crypto.decrypt(&entry.encrypted_data).await?;
            let parse_result = serde_json::from_slice(&decrypted_data);
            // Zeroize decrypted plaintext containing the CA private key before
            // propagating any parse error, so key material is never left in
            // freed heap memory.
            zeroize::Zeroize::zeroize(&mut decrypted_data);
            let ca_data: serde_json::Value = parse_result?;

            let priv_key = ca_data["private_key"].as_str().map(|s| s.to_string());
            let pub_key = ca_data["public_key"].as_str().map(|s| s.to_string());

            if let (Some(priv_k), Some(pub_k)) = (priv_key, pub_key) {
                Some((priv_k, pub_k))
            } else {
                None
            }
        } else {
            None
        };

        {
            let mut engine_lock = self.engine.write().await;
            if self.initialized.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(());
            }

            if let Some((priv_key, pub_key)) = maybe_ca {
                let config = SshConfig {
                    default_lease_ttl: 3600,
                    max_lease_ttl: SSH_MAX_LEASE_TTL,
                    allowed_users: vec![],
                    allowed_extensions: vec![],
                    ca_private_key: Some(priv_key),
                    ca_public_key: Some(pub_key),
                };

                let mut engine = SshEngine::new(config);
                engine.enable();
                *engine_lock = engine;
                info!("SSH Engine initialized with loaded CA");
            } else {
                // Initialize engine but disabled or without CA
                let mut engine = SshEngine::new(SshConfig {
                    default_lease_ttl: 3600,
                    max_lease_ttl: SSH_MAX_LEASE_TTL,
                    allowed_users: vec![],
                    allowed_extensions: vec![],
                    ca_private_key: None,
                    ca_public_key: None,
                });
                engine.enable();
                *engine_lock = engine;
                info!("No SSH CA found in storage. SSH Engine running without CA.");
            }

            self.initialized.store(true, std::sync::atomic::Ordering::Release);
        }

        Ok(())
    }

    pub async fn generate_ca(&self) -> std::result::Result<String, SshServiceError> {
        self.ensure_initialized().await?;

        let mut engine_lock = self.engine.write().await;

        // Guard: prevent overwriting an existing CA which would silently
        // invalidate all previously signed certificates.
        let existing = engine_lock.read("config/ca").await
            .map_err(|e| SshServiceError::Internal(e.to_string()))?;
        if existing.is_some() {
            return Err(SshServiceError::Conflict(
                "SSH CA already exists. Delete the existing CA first to regenerate.".to_string(),
            ));
        }

        // Generate the CA on a temporary engine so that the real engine is NOT
        // mutated until storage persistence succeeds.  This avoids an
        // irrecoverable inconsistency where the in-memory engine holds a CA
        // that was never persisted (blocking retries via the conflict guard).
        let mut temp_engine = SshEngine::new(SshConfig {
            default_lease_ttl: 3600,
            max_lease_ttl: SSH_MAX_LEASE_TTL,
            allowed_users: vec![],
            allowed_extensions: vec![],
            ca_private_key: None,
            ca_public_key: None,
        });
        temp_engine.enable();

        let (priv_pem, pub_str) = temp_engine.generate_ca()
            .map_err(|e| SshServiceError::Internal(format!("Failed to generate SSH CA: {}", e)))?;

        let ca_data = json!({
            "private_key": priv_pem,
            "public_key": pub_str.clone(),
            "created_at": Utc::now().to_rfc3339(),
        });

        let mut ca_bytes = serde_json::to_vec(&ca_data)?;
        let encrypt_result = self.crypto.encrypt_data(&ca_bytes).await;
        // Zeroize sensitive plaintext containing the CA private key after encryption
        zeroize::Zeroize::zeroize(&mut ca_bytes);
        let encrypted_data = encrypt_result?;

        let entry = SecretEntry::new(
            SSH_CA_STORAGE_PATH.to_string(),
            encrypted_data,
            EncryptionMetadata::default(),
            SecurityLevel::TopSecret,
            uuid::Uuid::new_v4(), // System owned
        );

        self.storage.store(&entry).await
            .map_err(|e| SshServiceError::Internal(format!("Failed to persist SSH CA: {}", e)))?;

        // Storage succeeded — now atomically replace the real engine with the
        // one that holds the new CA keys (mirrors the PKI service pattern).
        *engine_lock = temp_engine;

        info!("Generated and persisted new SSH CA");
        Ok(pub_str)
    }

    pub async fn get_ca_public_key(&self) -> std::result::Result<Option<String>, SshServiceError> {
        self.ensure_initialized().await?;
        let engine = self.engine.read().await;

        // SshEngine read "config/ca" returns CA public key
        let res = engine.read("config/ca").await
            .map_err(|e| SshServiceError::Internal(e.to_string()))?;

        if let Some(secret) = res {
            Ok(secret.data.get("public_key").and_then(|v| v.as_str()).map(|s| s.to_string()))
        } else {
            Ok(None)
        }
    }

    pub async fn sign_key(
        &self,
        public_key: &str,
        valid_principals: Vec<String>,
        ttl: u64,
    ) -> std::result::Result<String, SshServiceError> {
        self.ensure_initialized().await?;
        let engine = self.engine.read().await;

        let signed_cert = engine.sign_key(public_key, valid_principals, ttl)
            .map_err(|e| match &e {
                SecretError::InvalidSecretData(_) => {
                    SshServiceError::BadRequest(format!("Failed to sign key: {}", e))
                }
                SecretError::InvalidConfiguration(_) => {
                    SshServiceError::Internal(format!("SSH CA not properly configured: {}", e))
                }
                _ => SshServiceError::Internal(format!("Failed to sign key: {}", e)),
            })?;

        Ok(signed_cert)
    }
}
