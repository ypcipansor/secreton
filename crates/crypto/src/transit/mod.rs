//! Transit Engine - Encryption as a Service
//!
//! This module provides a comprehensive transit encryption service similar to HashiCorp Vault's 
//! transit secrets engine, with enhanced RustCrypto integration for cryptographic operations.
//! 
//! Key features:
//! - Multiple encryption algorithms (AES-GCM, ChaCha20Poly1305, RSA, ECC)
//! - Key rotation and versioning
//! - Digital signatures (Ed25519, ECDSA, RSA-PSS)
//! - Key derivation and random data generation
//! - Transit key management with lifecycle policies
//! - Batch operations for high throughput
//! - Audit logging for compliance

pub mod algorithms;
pub mod keys;
pub mod operations;
pub mod policies;
pub mod batch;

pub use algorithms::*;
pub use keys::*;
pub use operations::*;
pub use policies::*;
pub use batch::*;

use crate::error::{CryptoResult, CryptoError};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use chrono::{DateTime, Utc};

/// Transit engine for encryption as a service
#[derive(Debug)]
pub struct TransitEngine {
    /// Storage for transit keys
    keys: Arc<RwLock<HashMap<String, TransitKey>>>,
    
    /// Global policies for the transit engine
    policies: TransitPolicies,
    
    /// Audit logger
    audit: Option<Box<dyn AuditLogger + Send + Sync>>,
}

impl TransitEngine {
    /// Create a new transit engine
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            policies: TransitPolicies::default(),
            audit: None,
        }
    }
    
    /// Create transit engine with custom policies
    pub fn with_policies(policies: TransitPolicies) -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            policies,
            audit: None,
        }
    }
    
    /// Set audit logger
    pub fn with_audit_logger(mut self, logger: Box<dyn AuditLogger + Send + Sync>) -> Self {
        self.audit = Some(logger);
        self
    }
    
    /// Create a new transit key
    pub async fn create_key(
        &self,
        name: String,
        key_type: KeyType,
        options: Option<KeyOptions>,
    ) -> CryptoResult<()> {
        let mut keys = self.keys.write().await;
        
        if keys.contains_key(&name) {
            return Err(CryptoError::KeyAlreadyExists(name));
        }
        
        let transit_key = TransitKey::new(name.clone(), key_type, options.unwrap_or_default())?;
        
        // Audit log
        if let Some(ref audit) = self.audit {
            audit.log_key_creation(&name, &key_type).await;
        }
        
        keys.insert(name.clone(), transit_key);
        info!("Created transit key: {}", name);
        
        Ok(())
    }
    
    /// List all transit keys
    pub async fn list_keys(&self) -> Vec<String> {
        let keys = self.keys.read().await;
        keys.keys().cloned().collect()
    }
    
    /// Get key information
    pub async fn get_key_info(&self, name: &str) -> CryptoResult<KeyInfo> {
        let keys = self.keys.read().await;
        let key = keys.get(name).ok_or_else(|| CryptoError::KeyNotFound(name.to_string()))?;
        Ok(key.info())
    }
    
    /// Rotate a transit key (create new version)
    pub async fn rotate_key(&self, name: &str) -> CryptoResult<u32> {
        let mut keys = self.keys.write().await;
        let key = keys.get_mut(name).ok_or_else(|| CryptoError::KeyNotFound(name.to_string()))?;
        
        let new_version = key.rotate()?;
        
        // Audit log
        if let Some(ref audit) = self.audit {
            audit.log_key_rotation(name, new_version).await;
        }
        
        info!("Rotated transit key: {} to version {}", name, new_version);
        Ok(new_version)
    }
    
    /// Delete a transit key
    pub async fn delete_key(&self, name: &str) -> CryptoResult<()> {
        let mut keys = self.keys.write().await;
        
        if !keys.contains_key(name) {
            return Err(CryptoError::KeyNotFound(name.to_string()));
        }
        
        keys.remove(name);
        
        // Audit log
        if let Some(ref audit) = self.audit {
            audit.log_key_deletion(name).await;
        }
        
        warn!("Deleted transit key: {}", name);
        Ok(())
    }
    
    /// Encrypt data using a transit key
    pub async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
        context: Option<&[u8]>,
        key_version: Option<u32>,
    ) -> CryptoResult<String> {
        let keys = self.keys.read().await;
        let key = keys.get(key_name).ok_or_else(|| CryptoError::KeyNotFound(key_name.to_string()))?;
        
        let result = key.encrypt(plaintext, context, key_version)?;
        
        // Audit log
        if let Some(ref audit) = self.audit {
            audit.log_encryption(key_name, plaintext.len()).await;
        }
        
        Ok(result)
    }
    
    /// Decrypt data using a transit key
    pub async fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &str,
        context: Option<&[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        let keys = self.keys.read().await;
        let key = keys.get(key_name).ok_or_else(|| CryptoError::KeyNotFound(key_name.to_string()))?;
        
        let result = key.decrypt(ciphertext, context)?;
        
        // Audit log
        if let Some(ref audit) = self.audit {
            audit.log_decryption(key_name, result.len()).await;
        }
        
        Ok(result)
    }
    
    /// Sign data using a transit key
    pub async fn sign(
        &self,
        key_name: &str,
        data: &[u8],
        algorithm: Option<SignatureAlgorithm>,
        key_version: Option<u32>,
    ) -> CryptoResult<String> {
        let keys = self.keys.read().await;
        let key = keys.get(key_name).ok_or_else(|| CryptoError::KeyNotFound(key_name.to_string()))?;
        
        let result = key.sign(data, algorithm, key_version)?;
        
        // Audit log
        if let Some(ref audit) = self.audit {
            audit.log_signing(key_name, data.len()).await;
        }
        
        Ok(result)
    }
    
    /// Verify signature using a transit key
    pub async fn verify(
        &self,
        key_name: &str,
        data: &[u8],
        signature: &str,
        algorithm: Option<SignatureAlgorithm>,
    ) -> CryptoResult<bool> {
        let keys = self.keys.read().await;
        let key = keys.get(key_name).ok_or_else(|| CryptoError::KeyNotFound(key_name.to_string()))?;
        
        let result = key.verify(data, signature, algorithm)?;
        
        // Audit log
        if let Some(ref audit) = self.audit {
            audit.log_verification(key_name, data.len(), result).await;
        }
        
        Ok(result)
    }
    
    /// Generate random data
    pub async fn random(&self, bytes: usize) -> CryptoResult<Vec<u8>> {
        if bytes > self.policies.max_random_bytes {
            return Err(CryptoError::InvalidParameter(
                format!("Requested {} bytes exceeds maximum {}", bytes, self.policies.max_random_bytes)
            ));
        }
        
        let mut random_data = vec![0u8; bytes];
        rand::Rng::fill(&mut rand::thread_rng(), &mut random_data[..]);
        
        Ok(random_data)
    }
    
    /// Derive key using HKDF
    pub async fn derive_key(
        &self,
        key_name: &str,
        context: &[u8],
        length: usize,
    ) -> CryptoResult<Vec<u8>> {
        let keys = self.keys.read().await;
        let key = keys.get(key_name).ok_or_else(|| CryptoError::KeyNotFound(key_name.to_string()))?;
        
        key.derive_key(context, length)
    }
    
    /// Process batch operations
    pub async fn batch_operation(&self, operations: Vec<BatchOperation>) -> Vec<BatchResult> {
        let mut results = Vec::with_capacity(operations.len());
        
        for operation in operations {
            let result = self.process_batch_operation(operation).await;
            results.push(result);
        }
        
        results
    }
    
    /// Process a single batch operation
    async fn process_batch_operation(&self, operation: BatchOperation) -> BatchResult {
        match operation.operation_type {
            BatchOperationType::Encrypt => {
                match self.encrypt(
                    &operation.key_name,
                    &operation.data,
                    operation.context.as_deref(),
                    operation.key_version,
                ).await {
                    Ok(ciphertext) => BatchResult::success(operation.id, ciphertext.into_bytes()),
                    Err(e) => BatchResult::error(operation.id, e.to_string()),
                }
            }
            BatchOperationType::Decrypt => {
                match String::from_utf8(operation.data.clone()) {
                    Ok(ciphertext) => {
                        match self.decrypt(
                            &operation.key_name,
                            &ciphertext,
                            operation.context.as_deref(),
                        ).await {
                            Ok(plaintext) => BatchResult::success(operation.id, plaintext),
                            Err(e) => BatchResult::error(operation.id, e.to_string()),
                        }
                    }
                    Err(e) => BatchResult::error(operation.id, format!("Invalid UTF-8: {}", e)),
                }
            }
            BatchOperationType::Sign => {
                match self.sign(
                    &operation.key_name,
                    &operation.data,
                    operation.signature_algorithm,
                    operation.key_version,
                ).await {
                    Ok(signature) => BatchResult::success(operation.id, signature.into_bytes()),
                    Err(e) => BatchResult::error(operation.id, e.to_string()),
                }
            }
        }
    }
}

/// Audit logger trait for transit operations
#[async_trait::async_trait]
pub trait AuditLogger {
    async fn log_key_creation(&self, name: &str, key_type: &KeyType);
    async fn log_key_rotation(&self, name: &str, version: u32);
    async fn log_key_deletion(&self, name: &str);
    async fn log_encryption(&self, key_name: &str, data_len: usize);
    async fn log_decryption(&self, key_name: &str, data_len: usize);
    async fn log_signing(&self, key_name: &str, data_len: usize);
    async fn log_verification(&self, key_name: &str, data_len: usize, result: bool);
}

/// Default audit logger implementation
#[derive(Debug)]
pub struct DefaultAuditLogger;

#[async_trait::async_trait]
impl AuditLogger for DefaultAuditLogger {
    async fn log_key_creation(&self, name: &str, key_type: &KeyType) {
        info!("AUDIT: Key created - name: {}, type: {:?}", name, key_type);
    }
    
    async fn log_key_rotation(&self, name: &str, version: u32) {
        info!("AUDIT: Key rotated - name: {}, new_version: {}", name, version);
    }
    
    async fn log_key_deletion(&self, name: &str) {
        warn!("AUDIT: Key deleted - name: {}", name);
    }
    
    async fn log_encryption(&self, key_name: &str, data_len: usize) {
        info!("AUDIT: Encryption - key: {}, data_len: {}", key_name, data_len);
    }
    
    async fn log_decryption(&self, key_name: &str, data_len: usize) {
        info!("AUDIT: Decryption - key: {}, data_len: {}", key_name, data_len);
    }
    
    async fn log_signing(&self, key_name: &str, data_len: usize) {
        info!("AUDIT: Signing - key: {}, data_len: {}", key_name, data_len);
    }
    
    async fn log_verification(&self, key_name: &str, data_len: usize, result: bool) {
        info!("AUDIT: Verification - key: {}, data_len: {}, valid: {}", key_name, data_len, result);
    }
}

impl Default for TransitEngine {
    fn default() -> Self {
        Self::new()
    }
}
