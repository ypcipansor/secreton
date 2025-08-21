//! High-level transit operations with comprehensive error handling

use crate::error::{CryptoResult, CryptoError};
use crate::transit::{TransitEngine, KeyType, KeyOptions, SignatureAlgorithm};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tracing::{info, warn, error, debug};

/// High-level transit operations wrapper
#[derive(Debug)]
pub struct TransitOperations {
    engine: TransitEngine,
    operation_stats: OperationStats,
}

impl TransitOperations {
    /// Create new transit operations
    pub fn new(engine: TransitEngine) -> Self {
        Self {
            engine,
            operation_stats: OperationStats::new(),
        }
    }
    
    /// Create a new encryption key with comprehensive options
    pub async fn create_encryption_key(
        &mut self,
        name: String,
        key_type: KeyType,
        options: CreateKeyRequest,
    ) -> CryptoResult<CreateKeyResponse> {
        let start_time = std::time::Instant::now();
        
        // Validate key name
        if name.is_empty() || name.len() > 64 {
            return Err(CryptoError::InvalidParameter("Key name must be 1-64 characters".to_string()));
        }
        
        // Create key options
        let key_options = KeyOptions {
            exportable: options.exportable,
            usage: options.allowed_operations.clone(),
            min_decryption_version: options.min_decryption_version,
            allow_plaintext_backup: options.allow_plaintext_backup,
            context: options.derivation_context.clone(),
            metadata: options.metadata.clone(),
        };
        
        // Create the key
        self.engine.create_key(name.clone(), key_type.clone(), Some(key_options)).await?;
        
        let processing_time = start_time.elapsed();
        self.operation_stats.record_key_creation(processing_time);
        
        info!("Created encryption key: {} (type: {:?})", name, key_type);
        
        Ok(CreateKeyResponse {
            name: name.clone(),
            key_type,
            created_at: Utc::now(),
            latest_version: 1,
            processing_time_ms: processing_time.as_millis() as u64,
        })
    }
    
    /// Encrypt data with additional options
    pub async fn encrypt_data(&mut self, request: EncryptRequest) -> CryptoResult<EncryptResponse> {
        let start_time = std::time::Instant::now();
        
        // Validate input
        if request.key_name.is_empty() {
            return Err(CryptoError::InvalidParameter("Key name cannot be empty".to_string()));
        }
        
        if request.plaintext.is_empty() {
            return Err(CryptoError::InvalidParameter("Plaintext cannot be empty".to_string()));
        }
        
        // Perform encryption
        let ciphertext = self.engine.encrypt(
            &request.key_name,
            &request.plaintext,
            request.context.as_deref(),
            request.key_version,
        ).await?;
        
        let processing_time = start_time.elapsed();
        self.operation_stats.record_encryption(processing_time, request.plaintext.len());
        
        debug!("Encrypted {} bytes with key: {}", request.plaintext.len(), request.key_name);
        
        Ok(EncryptResponse {
            key_name: request.key_name,
            ciphertext,
            key_version: request.key_version,
            processing_time_ms: processing_time.as_millis() as u64,
        })
    }
    
    /// Decrypt data with validation
    pub async fn decrypt_data(&mut self, request: DecryptRequest) -> CryptoResult<DecryptResponse> {
        let start_time = std::time::Instant::now();
        
        // Validate input
        if request.key_name.is_empty() {
            return Err(CryptoError::InvalidParameter("Key name cannot be empty".to_string()));
        }
        
        if request.ciphertext.is_empty() {
            return Err(CryptoError::InvalidParameter("Ciphertext cannot be empty".to_string()));
        }
        
        // Perform decryption
        let plaintext = self.engine.decrypt(
            &request.key_name,
            &request.ciphertext,
            request.context.as_deref(),
        ).await?;
        
        let processing_time = start_time.elapsed();
        self.operation_stats.record_decryption(processing_time, plaintext.len());
        
        debug!("Decrypted {} bytes with key: {}", plaintext.len(), request.key_name);
        
        Ok(DecryptResponse {
            key_name: request.key_name,
            plaintext,
            processing_time_ms: processing_time.as_millis() as u64,
        })
    }
    
    /// Sign data with comprehensive options
    pub async fn sign_data(&mut self, request: SignRequest) -> CryptoResult<SignResponse> {
        let start_time = std::time::Instant::now();
        
        // Validate input
        if request.key_name.is_empty() {
            return Err(CryptoError::InvalidParameter("Key name cannot be empty".to_string()));
        }
        
        if request.data.is_empty() {
            return Err(CryptoError::InvalidParameter("Data to sign cannot be empty".to_string()));
        }
        
        // Perform signing
        let signature = self.engine.sign(
            &request.key_name,
            &request.data,
            request.algorithm,
            request.key_version,
        ).await?;
        
        let processing_time = start_time.elapsed();
        self.operation_stats.record_signing(processing_time, request.data.len());
        
        debug!("Signed {} bytes with key: {}", request.data.len(), request.key_name);
        
        Ok(SignResponse {
            key_name: request.key_name,
            signature,
            algorithm: request.algorithm,
            key_version: request.key_version,
            processing_time_ms: processing_time.as_millis() as u64,
        })
    }
    
    /// Verify signature with validation
    pub async fn verify_signature(&mut self, request: VerifyRequest) -> CryptoResult<VerifyResponse> {
        let start_time = std::time::Instant::now();
        
        // Validate input
        if request.key_name.is_empty() {
            return Err(CryptoError::InvalidParameter("Key name cannot be empty".to_string()));
        }
        
        if request.data.is_empty() {
            return Err(CryptoError::InvalidParameter("Data cannot be empty".to_string()));
        }
        
        if request.signature.is_empty() {
            return Err(CryptoError::InvalidParameter("Signature cannot be empty".to_string()));
        }
        
        // Perform verification
        let is_valid = self.engine.verify(
            &request.key_name,
            &request.data,
            &request.signature,
            request.algorithm,
        ).await?;
        
        let processing_time = start_time.elapsed();
        self.operation_stats.record_verification(processing_time, request.data.len(), is_valid);
        
        debug!("Verified signature for {} bytes with key: {} (valid: {})", 
               request.data.len(), request.key_name, is_valid);
        
        Ok(VerifyResponse {
            key_name: request.key_name,
            is_valid,
            algorithm: request.algorithm,
            processing_time_ms: processing_time.as_millis() as u64,
        })
    }
    
    /// Rotate key with validation
    pub async fn rotate_key(&mut self, request: RotateKeyRequest) -> CryptoResult<RotateKeyResponse> {
        let start_time = std::time::Instant::now();
        
        if request.key_name.is_empty() {
            return Err(CryptoError::InvalidParameter("Key name cannot be empty".to_string()));
        }
        
        let new_version = self.engine.rotate_key(&request.key_name).await?;
        
        let processing_time = start_time.elapsed();
        self.operation_stats.record_key_rotation(processing_time);
        
        info!("Rotated key: {} to version {}", request.key_name, new_version);
        
        Ok(RotateKeyResponse {
            key_name: request.key_name,
            new_version,
            rotated_at: Utc::now(),
            processing_time_ms: processing_time.as_millis() as u64,
        })
    }
    
    /// Generate random data
    pub async fn generate_random(&mut self, request: RandomRequest) -> CryptoResult<RandomResponse> {
        let start_time = std::time::Instant::now();
        
        if request.bytes == 0 || request.bytes > 1024 * 1024 { // Max 1MB
            return Err(CryptoError::InvalidParameter("Bytes must be between 1 and 1048576".to_string()));
        }
        
        let random_data = self.engine.random(request.bytes).await?;
        
        let processing_time = start_time.elapsed();
        
        debug!("Generated {} random bytes", request.bytes);
        
        Ok(RandomResponse {
            random_data,
            bytes: request.bytes,
            format: request.format,
            processing_time_ms: processing_time.as_millis() as u64,
        })
    }
    
    /// Derive key from existing key
    pub async fn derive_key(&mut self, request: DeriveKeyRequest) -> CryptoResult<DeriveKeyResponse> {
        let start_time = std::time::Instant::now();
        
        if request.key_name.is_empty() {
            return Err(CryptoError::InvalidParameter("Key name cannot be empty".to_string()));
        }
        
        if request.context.is_empty() {
            return Err(CryptoError::InvalidParameter("Derivation context cannot be empty".to_string()));
        }
        
        if request.length == 0 || request.length > 1024 { // Max 1KB derived key
            return Err(CryptoError::InvalidParameter("Length must be between 1 and 1024".to_string()));
        }
        
        let derived_key = self.engine.derive_key(&request.key_name, &request.context, request.length).await?;
        
        let processing_time = start_time.elapsed();
        
        debug!("Derived {} byte key from: {}", request.length, request.key_name);
        
        Ok(DeriveKeyResponse {
            key_name: request.key_name,
            derived_key,
            length: request.length,
            processing_time_ms: processing_time.as_millis() as u64,
        })
    }
    
    /// Get operation statistics
    pub fn get_stats(&self) -> &OperationStats {
        &self.operation_stats
    }
    
    /// Reset operation statistics
    pub fn reset_stats(&mut self) {
        self.operation_stats = OperationStats::new();
    }
}

// Request/Response types for operations

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub exportable: bool,
    pub allowed_operations: Vec<crate::transit::KeyUsage>,
    pub min_decryption_version: u32,
    pub allow_plaintext_backup: bool,
    pub derivation_context: Option<Vec<u8>>,
    pub metadata: HashMap<String, String>,
}

impl Default for CreateKeyRequest {
    fn default() -> Self {
        Self {
            exportable: false,
            allowed_operations: vec![
                crate::transit::KeyUsage::Encrypt,
                crate::transit::KeyUsage::Decrypt,
            ],
            min_decryption_version: 1,
            allow_plaintext_backup: false,
            derivation_context: None,
            metadata: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateKeyResponse {
    pub name: String,
    pub key_type: KeyType,
    pub created_at: DateTime<Utc>,
    pub latest_version: u32,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub key_name: String,
    pub plaintext: Vec<u8>,
    pub context: Option<Vec<u8>>,
    pub key_version: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub key_name: String,
    pub ciphertext: String,
    pub key_version: Option<u32>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub key_name: String,
    pub ciphertext: String,
    pub context: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub key_name: String,
    pub plaintext: Vec<u8>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub key_name: String,
    pub data: Vec<u8>,
    pub algorithm: Option<SignatureAlgorithm>,
    pub key_version: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub key_name: String,
    pub signature: String,
    pub algorithm: Option<SignatureAlgorithm>,
    pub key_version: Option<u32>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub key_name: String,
    pub data: Vec<u8>,
    pub signature: String,
    pub algorithm: Option<SignatureAlgorithm>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub key_name: String,
    pub is_valid: bool,
    pub algorithm: Option<SignatureAlgorithm>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateKeyRequest {
    pub key_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateKeyResponse {
    pub key_name: String,
    pub new_version: u32,
    pub rotated_at: DateTime<Utc>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomRequest {
    pub bytes: usize,
    pub format: RandomFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RandomFormat {
    Base64,
    Hex,
    Raw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomResponse {
    pub random_data: Vec<u8>,
    pub bytes: usize,
    pub format: RandomFormat,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeriveKeyRequest {
    pub key_name: String,
    pub context: Vec<u8>,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeriveKeyResponse {
    pub key_name: String,
    pub derived_key: Vec<u8>,
    pub length: usize,
    pub processing_time_ms: u64,
}

/// Operation statistics tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationStats {
    pub key_creations: u64,
    pub key_rotations: u64,
    pub encryptions: u64,
    pub decryptions: u64,
    pub signings: u64,
    pub verifications: u64,
    pub successful_verifications: u64,
    pub total_bytes_encrypted: u64,
    pub total_bytes_decrypted: u64,
    pub total_bytes_signed: u64,
    pub average_encryption_time_ms: f64,
    pub average_decryption_time_ms: f64,
    pub average_signing_time_ms: f64,
    pub start_time: DateTime<Utc>,
    pub last_operation: Option<DateTime<Utc>>,
}

impl OperationStats {
    pub fn new() -> Self {
        Self {
            key_creations: 0,
            key_rotations: 0,
            encryptions: 0,
            decryptions: 0,
            signings: 0,
            verifications: 0,
            successful_verifications: 0,
            total_bytes_encrypted: 0,
            total_bytes_decrypted: 0,
            total_bytes_signed: 0,
            average_encryption_time_ms: 0.0,
            average_decryption_time_ms: 0.0,
            average_signing_time_ms: 0.0,
            start_time: Utc::now(),
            last_operation: None,
        }
    }
    
    pub fn record_key_creation(&mut self, duration: std::time::Duration) {
        self.key_creations += 1;
        self.last_operation = Some(Utc::now());
    }
    
    pub fn record_key_rotation(&mut self, duration: std::time::Duration) {
        self.key_rotations += 1;
        self.last_operation = Some(Utc::now());
    }
    
    pub fn record_encryption(&mut self, duration: std::time::Duration, bytes: usize) {
        self.encryptions += 1;
        self.total_bytes_encrypted += bytes as u64;
        self.update_average_time(&mut self.average_encryption_time_ms, duration, self.encryptions);
        self.last_operation = Some(Utc::now());
    }
    
    pub fn record_decryption(&mut self, duration: std::time::Duration, bytes: usize) {
        self.decryptions += 1;
        self.total_bytes_decrypted += bytes as u64;
        self.update_average_time(&mut self.average_decryption_time_ms, duration, self.decryptions);
        self.last_operation = Some(Utc::now());
    }
    
    pub fn record_signing(&mut self, duration: std::time::Duration, bytes: usize) {
        self.signings += 1;
        self.total_bytes_signed += bytes as u64;
        self.update_average_time(&mut self.average_signing_time_ms, duration, self.signings);
        self.last_operation = Some(Utc::now());
    }
    
    pub fn record_verification(&mut self, duration: std::time::Duration, bytes: usize, valid: bool) {
        self.verifications += 1;
        if valid {
            self.successful_verifications += 1;
        }
        self.last_operation = Some(Utc::now());
    }
    
    fn update_average_time(&mut self, avg: &mut f64, duration: std::time::Duration, count: u64) {
        let new_time = duration.as_millis() as f64;
        *avg = (*avg * (count - 1) as f64 + new_time) / count as f64;
    }
    
    pub fn verification_success_rate(&self) -> f64 {
        if self.verifications == 0 {
            return 0.0;
        }
        (self.successful_verifications as f64 / self.verifications as f64) * 100.0
    }
}

impl Default for OperationStats {
    fn default() -> Self {
        Self::new()
    }
}
