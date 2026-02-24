//! Persistent PKI Service
//!
//! Handles persistence of PKI state (CA keys, certificates) using the StorageBackend
//! and CryptoService. Wraps the in-memory PkiEngine.

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, anyhow};
use tracing::{info, warn, error};
use serde_json::json;

use secreton_storage::{StorageBackend, SecretEntry, EncryptionMetadata, SecurityLevel};
use secreton_secrets_pki::{PkiEngine, PkiConfig, CertificateRequest, CertificateResponse};
use crate::services::crypto::CryptoService;

const CA_STORAGE_PATH: &str = "sys/pki/ca";
const CA_CONFIG_PATH: &str = "sys/pki/config";

pub struct PkiPersistentService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    engine: Arc<RwLock<PkiEngine>>,
    initialized: std::sync::atomic::AtomicBool,
}

impl PkiPersistentService {
    pub fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
    ) -> Self {
        // Initialize engine with empty config initially
        let config = PkiConfig {
            default_lease_ttl: 3600,
            max_lease_ttl: 86400 * 365,
            ca_cert: None,
            ca_key: None,
            crl: None,
        };
        let engine = PkiEngine::new(config);

        Self {
            storage,
            crypto,
            engine: Arc::new(RwLock::new(engine)),
            initialized: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Ensure the service is initialized by loading CA from storage
    pub async fn ensure_initialized(&self) -> Result<()> {
        if self.initialized.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }

        // Try to load CA from storage
        if let Some(entry) = self.storage.get_by_path(CA_STORAGE_PATH).await? {
            // Decrypt the data
            let decrypted_data = self.crypto.decrypt(&entry.encrypted_data).await?;
            let ca_data: serde_json::Value = serde_json::from_slice(&decrypted_data)?;

            let cert_pem = ca_data["certificate"].as_str().ok_or_else(|| anyhow!("Missing certificate in storage"))?;
            let key_pem = ca_data["private_key"].as_str().ok_or_else(|| anyhow!("Missing private key in storage"))?;

            // Re-initialize engine with loaded CA
            let config = PkiConfig {
                default_lease_ttl: 3600,
                max_lease_ttl: 86400 * 365,
                ca_cert: Some(cert_pem.to_string()),
                ca_key: Some(key_pem.to_string()),
                crl: None,
            };

            // Acquire write lock to update engine
            let mut engine_lock = self.engine.write().await;
            *engine_lock = PkiEngine::new(config);

            info!("PKI Engine initialized with loaded CA");
        } else {
            info!("No CA found in storage. PKI Engine running in uninitialized mode.");
        }

        self.initialized.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Generate a new Root CA
    pub async fn generate_root_ca(&self, common_name: &str, organization: &str) -> Result<(String, String)> {
        // Ensure initialized to load any existing CA from storage before checking/generating
        self.ensure_initialized().await?;

        // Acquire write lock immediately to prevent race conditions (TOCTOU)
        // We hold this lock for the entire duration of the check-generate-store sequence.
        let mut engine_lock = self.engine.write().await;

        // Guard: Check if CA already exists in the engine config
        if engine_lock.has_ca_configured() {
             return Err(anyhow!("Root CA already exists. Use force if you really intend to overwrite."));
        }

        // Generate via engine logic
        let (cert_pem, key_pem) = engine_lock.generate_root_ca(common_name, organization).await
            .map_err(|e| anyhow!("Failed to generate Root CA: {}", e))?;

        // Store in storage
        let ca_data = json!({
            "certificate": cert_pem,
            "private_key": key_pem,
            "common_name": common_name,
            "organization": organization,
            "created_at": chrono::Utc::now().to_rfc3339(),
        });

        let ca_bytes = serde_json::to_vec(&ca_data)?;
        let encrypted_data = self.crypto.encrypt_data(&ca_bytes).await?;

        let entry = SecretEntry::new(
            CA_STORAGE_PATH.to_string(),
            encrypted_data,
            EncryptionMetadata::default(),
            SecurityLevel::TopSecret,
            uuid::Uuid::new_v4(), // System owned
        );

        // This storage operation is async and outside the lock? No, we are holding the lock.
        // This blocks other readers/writers which is what we want for correctness here.
        if let Err(e) = self.storage.store(&entry).await {
             return Err(anyhow!("Failed to persist Root CA: {}", e));
        }

        // Update in-memory engine configuration
        let config = PkiConfig {
            default_lease_ttl: 3600,
            max_lease_ttl: 86400 * 365,
            ca_cert: Some(cert_pem.clone()),
            ca_key: Some(key_pem.clone()),
            crl: None,
        };

        // Replace the engine instance with the new configured one
        *engine_lock = PkiEngine::new(config);

        info!("Generated and persisted new Root CA: {}", common_name);

        Ok((cert_pem, key_pem))
    }

    /// Get the current CA Certificate (PEM)
    pub async fn get_ca_pem(&self) -> Result<Option<String>> {
        self.ensure_initialized().await?;
        let engine = self.engine.read().await;

        if !engine.has_ca_configured() {
            return Ok(None);
        }

        let info = engine.get_ca_info().await;

        match info {
            Ok(ca_info) => Ok(Some(ca_info.certificate)),
            Err(_) => Ok(None),
        }
    }

    /// Issue a certificate
    pub async fn issue_certificate(&self, req: CertificateRequest) -> Result<CertificateResponse> {
        self.ensure_initialized().await?;

        let engine = self.engine.read().await;

        // Ensure CA is configured
        if !engine.has_ca_configured() {
            return Err(anyhow!("PKI Engine not initialized with a Root CA. Please generate one first."));
        }

        let response = engine.generate_certificate(&req).await
            .map_err(|e| anyhow!("Failed to issue certificate: {}", e))?;

        // Persist the issued certificate
        // Path: sys/pki/certs/{serial_number}
        let cert_path = format!("sys/pki/certs/{}", response.serial_number);

        let cert_data = json!({
            "serial_number": response.serial_number,
            "certificate": response.certificate,
            // We typically don't store the private key of issued certs if we returned it,
            // but for recovery maybe? Vault doesn't usually store issued private keys unless requested.
            // But here we might want to log it.
            // Let's store metadata.
            "common_name": req.common_name,
            "issued_at": chrono::Utc::now().to_rfc3339(),
            "expires_at": response.expiration.to_rfc3339(),
        });

        let cert_bytes = serde_json::to_vec(&cert_data)?;
        let encrypted_data = self.crypto.encrypt_data(&cert_bytes).await?;

        let entry = SecretEntry::new(
            cert_path,
            encrypted_data,
            EncryptionMetadata::default(),
            SecurityLevel::Confidential,
            uuid::Uuid::new_v4(), // System owned
        );

        // Best effort storage for issued certs log
        if let Err(e) = self.storage.store(&entry).await {
            warn!("Failed to persist issued certificate record: {}", e);
        }

        Ok(response)
    }
}
