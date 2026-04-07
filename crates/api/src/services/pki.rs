//! Persistent PKI Service
//!
//! Handles persistence of PKI state (CA keys, certificates) using the StorageBackend
//! and CryptoService. Wraps the in-memory PkiEngine.

use anyhow::{Result, anyhow};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::services::crypto::CryptoService;
use secreton_secrets_pki::{CertificateRequest, CertificateResponse, PkiConfig, PkiEngine};
use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend};

/// Categorised service error that handlers can map to the appropriate HTTP status.
#[derive(Debug)]
pub enum PkiServiceError {
    /// The requested resource was not found (→ 404).
    NotFound(String),
    /// A conflicting state prevents the operation (→ 409).
    Conflict(String),
    /// A client-supplied value is invalid (→ 400).
    BadRequest(String),
    /// Any other unexpected failure (→ 500).
    Internal(String),
}

impl std::fmt::Display for PkiServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "{}", msg),
            Self::Conflict(msg) => write!(f, "{}", msg),
            Self::BadRequest(msg) => write!(f, "{}", msg),
            Self::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<anyhow::Error> for PkiServiceError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

const CA_STORAGE_PATH: &str = "sys/pki/ca";

pub struct PkiPersistentService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    engine: Arc<RwLock<PkiEngine>>,
    initialized: std::sync::atomic::AtomicBool,
}

impl PkiPersistentService {
    pub fn new(storage: Arc<dyn StorageBackend + Send + Sync>, crypto: Arc<CryptoService>) -> Self {
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
        if self.initialized.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }

        // Try to load CA from storage BEFORE acquiring the write lock so that a
        // storage failure does not leave the engine in a half-initialised state.
        let maybe_config = if let Some(entry) = self.storage.get_by_path(CA_STORAGE_PATH).await? {
            let mut decrypted_data = self.crypto.decrypt(&entry.encrypted_data).await?;
            let parse_result = serde_json::from_slice(&decrypted_data);
            // Zeroize decrypted plaintext containing the CA private key before
            // propagating any parse error, so key material is never left in
            // freed heap memory.
            zeroize::Zeroize::zeroize(&mut decrypted_data);
            let ca_data: serde_json::Value = parse_result?;

            let cert_pem = ca_data["certificate"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing certificate in storage"))?
                .to_string();
            let key_pem = ca_data["private_key"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing private key in storage"))?
                .to_string();

            Some(PkiConfig {
                default_lease_ttl: 3600,
                max_lease_ttl: 86400 * 365,
                ca_cert: Some(cert_pem),
                ca_key: Some(key_pem),
                crl: None,
            })
        } else {
            None
        };

        // Acquire write lock to update engine; re-check the flag inside the
        // lock to prevent redundant initialization when concurrent callers
        // race past the initial check.
        {
            let mut engine_lock = self.engine.write().await;
            if self.initialized.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(());
            }
            if let Some(config) = maybe_config {
                *engine_lock = PkiEngine::new(config);
                info!("PKI Engine initialized with loaded CA");
            } else {
                info!("No CA found in storage. PKI Engine running in uninitialized mode.");
            }
            self.initialized
                .store(true, std::sync::atomic::Ordering::Release);
        }

        Ok(())
    }

    /// Generate a new Root CA and return a full `CertificateResponse` with
    /// real serial number and expiration parsed from the generated certificate.
    pub async fn generate_root_ca(
        &self,
        common_name: &str,
        organization: &str,
    ) -> std::result::Result<CertificateResponse, PkiServiceError> {
        // Ensure initialized to load any existing CA from storage before checking/generating
        self.ensure_initialized().await
            .map_err(|e| PkiServiceError::Internal(e.to_string()))?;

        // Acquire write lock immediately to prevent race conditions (TOCTOU)
        // We hold this lock for the entire duration of the check-generate-store sequence.
        let mut engine_lock = self.engine.write().await;

        // Guard: Check if CA already exists in the engine config
        if engine_lock.has_ca_configured() {
            return Err(PkiServiceError::Conflict(
                "Root CA already exists. Use force if you really intend to overwrite.".to_string(),
            ));
        }

        // Generate via engine logic
        let (cert_pem, key_pem) = engine_lock
            .generate_root_ca(common_name, organization)
            .await
            .map_err(|e| PkiServiceError::Internal(format!("Failed to generate Root CA: {}", e)))?;

        // Parse the generated certificate to extract real metadata
        let ca_info = engine_lock
            .parse_ca_cert_from_pem(&cert_pem)
            .map_err(|e| PkiServiceError::Internal(format!("Failed to parse generated Root CA: {}", e)))?;

        // Store in storage
        let ca_data = json!({
            "certificate": cert_pem,
            "private_key": key_pem,
            "common_name": common_name,
            "organization": organization,
            "created_at": chrono::Utc::now().to_rfc3339(),
        });

        let mut ca_bytes = serde_json::to_vec(&ca_data)
            .map_err(|e| PkiServiceError::Internal(e.to_string()))?;
        let encrypt_result = self.crypto.encrypt_data(&ca_bytes).await;
        // Zeroize sensitive plaintext containing the CA private key after encryption
        zeroize::Zeroize::zeroize(&mut ca_bytes);
        let encrypted_data = encrypt_result
            .map_err(|e| PkiServiceError::Internal(e.to_string()))?;

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
            return Err(PkiServiceError::Internal(format!("Failed to persist Root CA: {}", e)));
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

        Ok(CertificateResponse {
            certificate: cert_pem.clone(),
            private_key: key_pem,
            serial_number: ca_info.serial_number,
            issuing_ca: cert_pem,
            ca_chain: vec![],
            expiration: ca_info.valid_until,
            revocation_time: None,
        })
    }

    /// Get the current CA Certificate (PEM)
    pub async fn get_ca_pem(&self) -> std::result::Result<Option<String>, PkiServiceError> {
        self.ensure_initialized().await
            .map_err(|e| PkiServiceError::Internal(e.to_string()))?;
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
    pub async fn issue_certificate(
        &self,
        req: CertificateRequest,
    ) -> std::result::Result<CertificateResponse, PkiServiceError> {
        self.ensure_initialized().await
            .map_err(|e| PkiServiceError::Internal(e.to_string()))?;

        let engine = self.engine.read().await;

        // Ensure CA is configured
        if !engine.has_ca_configured() {
            return Err(PkiServiceError::BadRequest(
                "PKI Engine not initialized with a Root CA. Please generate one first.".to_string(),
            ));
        }

        let response = engine
            .generate_certificate(&req)
            .await
            .map_err(|e| PkiServiceError::Internal(format!("Failed to issue certificate: {}", e)))?;

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

        let cert_bytes = serde_json::to_vec(&cert_data)
            .map_err(|e| PkiServiceError::Internal(e.to_string()))?;
        let encrypted_data = self.crypto.encrypt_data(&cert_bytes).await
            .map_err(|e| PkiServiceError::Internal(e.to_string()))?;

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
