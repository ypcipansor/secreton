//! Transit Engine Integration Module
//! 
//! This module provides integration between the enhanced transit engine
//! and the existing Brankas core system, including API endpoints,
//! storage backend, and service management.

use crate::transit::{TransitEngine, TransitPolicies, BatchOperation, KeyType, KeyOptions};
use crate::error::{CryptoResult, CryptoError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Integration wrapper for the transit engine with Brankas core services
pub struct TransitIntegration {
    engine: TransitEngine,
    config: IntegrationConfig,
    metrics: Arc<RwLock<IntegrationMetrics>>,
}

/// Configuration for transit engine integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    /// Enable API endpoints for transit operations
    pub enable_api: bool,
    
    /// Enable storage backend integration
    pub enable_storage: bool,
    
    /// Enable audit logging integration
    pub enable_audit: bool,
    
    /// Enable metrics collection
    pub enable_metrics: bool,
    
    /// API configuration
    pub api: ApiConfig,
    
    /// Storage configuration
    pub storage: StorageConfig,
    
    /// Performance tuning
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Base path for transit API endpoints
    pub base_path: String,
    
    /// Enable authentication for API endpoints
    pub require_auth: bool,
    
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    
    /// Request size limits
    pub max_request_size: usize,
    pub max_batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend type
    pub backend: StorageBackend,
    
    /// Connection parameters
    pub connection: StorageConnection,
    
    /// Encryption settings for stored keys
    pub encryption: StorageEncryption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageBackend {
    Memory,
    File { path: String },
    Database { url: String },
    Vault { address: String, token: String },
    Consul { address: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConnection {
    pub timeout_ms: u64,
    pub max_retries: u32,
    pub connection_pool_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEncryption {
    pub enabled: bool,
    pub key_derivation: String,
    pub cipher: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub enable_per_key_limits: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub worker_threads: usize,
    pub max_concurrent_operations: usize,
    pub operation_timeout_ms: u64,
    pub key_cache_size: usize,
    pub key_cache_ttl_seconds: u64,
}

/// Integration metrics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IntegrationMetrics {
    pub api_requests: u64,
    pub api_errors: u64,
    pub storage_operations: u64,
    pub storage_errors: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total_keys_managed: u64,
    pub total_operations_performed: u64,
    pub last_updated: DateTime<Utc>,
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            enable_api: true,
            enable_storage: true,
            enable_audit: true,
            enable_metrics: true,
            api: ApiConfig {
                base_path: "/v1/transit".to_string(),
                require_auth: true,
                rate_limit: RateLimitConfig {
                    requests_per_minute: 1000,
                    burst_size: 100,
                    enable_per_key_limits: true,
                },
                max_request_size: 1024 * 1024, // 1MB
                max_batch_size: 100,
            },
            storage: StorageConfig {
                backend: StorageBackend::File {
                    path: "./data/transit_keys".to_string(),
                },
                connection: StorageConnection {
                    timeout_ms: 5000,
                    max_retries: 3,
                    connection_pool_size: 10,
                },
                encryption: StorageEncryption {
                    enabled: true,
                    key_derivation: "PBKDF2".to_string(),
                    cipher: "AES-256-GCM".to_string(),
                },
            },
            performance: PerformanceConfig {
                worker_threads: num_cpus::get(),
                max_concurrent_operations: 1000,
                operation_timeout_ms: 30000,
                key_cache_size: 1000,
                key_cache_ttl_seconds: 3600,
            },
        }
    }
}

impl TransitIntegration {
    /// Create a new transit integration with default configuration
    pub fn new() -> Self {
        let config = IntegrationConfig::default();
        let policies = Self::create_policies_from_config(&config);
        let engine = TransitEngine::with_policies(policies);
        
        Self {
            engine,
            config,
            metrics: Arc::new(RwLock::new(IntegrationMetrics::default())),
        }
    }
    
    /// Create a new transit integration with custom configuration
    pub fn with_config(config: IntegrationConfig) -> Self {
        let policies = Self::create_policies_from_config(&config);
        let engine = TransitEngine::with_policies(policies);
        
        Self {
            engine,
            config,
            metrics: Arc::new(RwLock::new(IntegrationMetrics::default())),
        }
    }
    
    /// Create transit policies from integration configuration
    fn create_policies_from_config(config: &IntegrationConfig) -> TransitPolicies {
        let mut policies = TransitPolicies::default();
        
        // Configure performance limits
        policies.performance_limits.max_concurrent_operations = 
            config.performance.max_concurrent_operations;
        policies.performance_limits.max_batch_size = 
            config.api.max_batch_size;
        policies.performance_limits.operation_timeout = 
            std::time::Duration::from_millis(config.performance.operation_timeout_ms);
        
        // Configure rate limiting
        if config.api.rate_limit.enable_per_key_limits {
            policies.rate_limiting_policy.global_rate_limit = 
                config.api.rate_limit.requests_per_minute;
            policies.rate_limiting_policy.per_key_rate_limit = 
                Some(config.api.rate_limit.requests_per_minute / 10);
        }
        
        // Enable audit logging if configured
        policies.audit_policy.enabled = config.enable_audit;
        policies.audit_policy.log_all_operations = config.enable_audit;
        
        policies
    }
    
    /// Initialize the integration (setup storage, start services, etc.)
    pub async fn initialize(&mut self) -> CryptoResult<()> {
        if self.config.enable_storage {
            self.initialize_storage().await?;
        }
        
        if self.config.enable_metrics {
            self.initialize_metrics().await?;
        }
        
        self.update_metrics(|m| {
            m.last_updated = Utc::now();
        }).await;
        
        Ok(())
    }
    
    /// Initialize storage backend
    async fn initialize_storage(&self) -> CryptoResult<()> {
        match &self.config.storage.backend {
            StorageBackend::File { path } => {
                tokio::fs::create_dir_all(path).await
                    .map_err(|e| CryptoError::StorageError(format!("Failed to create storage directory: {}", e)))?;
            },
            StorageBackend::Database { url } => {
                // Initialize database connection
                // This would integrate with your database backend
            },
            StorageBackend::Vault { address, token } => {
                // Initialize Vault client
                // This would integrate with HashiCorp Vault
            },
            StorageBackend::Consul { address } => {
                // Initialize Consul client
                // This would integrate with HashiCorp Consul
            },
            StorageBackend::Memory => {
                // Memory backend needs no initialization
            },
        }
        
        Ok(())
    }
    
    /// Initialize metrics collection
    async fn initialize_metrics(&self) -> CryptoResult<()> {
        // Set up metrics collection, monitoring integration, etc.
        Ok(())
    }
    
    /// Get reference to the underlying transit engine
    pub fn engine(&self) -> &TransitEngine {
        &self.engine
    }
    
    /// Get integration configuration
    pub fn config(&self) -> &IntegrationConfig {
        &self.config
    }
    
    /// Get current metrics
    pub async fn get_metrics(&self) -> IntegrationMetrics {
        let guard = self.metrics.read().await;
        IntegrationMetrics {
            api_requests: guard.api_requests,
            api_errors: guard.api_errors,
            storage_operations: guard.storage_operations,
            storage_errors: guard.storage_errors,
            cache_hits: guard.cache_hits,
            cache_misses: guard.cache_misses,
            total_keys_managed: guard.total_keys_managed,
            total_operations_performed: guard.total_operations_performed,
            last_updated: guard.last_updated,
        }
    }
    
    /// Update metrics with a closure
    async fn update_metrics<F>(&self, f: F) 
    where 
        F: FnOnce(&mut IntegrationMetrics),
    {
        let mut metrics = self.metrics.write().await;
        f(&mut *metrics);
        metrics.last_updated = Utc::now();
    }
    
    /// Create a new key through the integration layer
    pub async fn create_key(
        &self,
        name: String,
        key_type: KeyType,
        options: Option<KeyOptions>,
    ) -> CryptoResult<KeyCreationResponse> {
        let start_time = std::time::Instant::now();
        
        // Validate request against configuration
        self.validate_key_creation(&name, &key_type, &options).await?;
        
        // Create key through transit engine
        let result = self.engine.create_key(name.clone(), key_type, options).await;
        
        // Update metrics
        self.update_metrics(|m| {
            m.total_keys_managed += 1;
            if result.is_err() {
                m.api_errors += 1;
            }
        }).await;
        
        match result {
            Ok(_) => Ok(KeyCreationResponse {
                name,
                created_at: Utc::now(),
                processing_time_ms: start_time.elapsed().as_millis() as u64,
            }),
            Err(e) => Err(e),
        }
    }
    
    /// Encrypt data through the integration layer
    pub async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
        context: Option<&[u8]>,
        key_version: Option<u32>,
    ) -> CryptoResult<EncryptionResponse> {
        let start_time = std::time::Instant::now();
        
        // Validate request
        self.validate_encryption_request(key_name, plaintext).await?;
        
        // Perform encryption
        let result = self.engine.encrypt(key_name, plaintext, context, key_version).await;
        
        // Update metrics
        self.update_metrics(|m| {
            m.total_operations_performed += 1;
            if result.is_err() {
                m.api_errors += 1;
            }
        }).await;
        
        match result {
            Ok(ciphertext) => Ok(EncryptionResponse {
                ciphertext,
                key_version: key_version.unwrap_or(1),
                processing_time_ms: start_time.elapsed().as_millis() as u64,
            }),
            Err(e) => Err(e),
        }
    }
    
    /// Decrypt data through the integration layer
    pub async fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &str,
        context: Option<&[u8]>,
    ) -> CryptoResult<DecryptionResponse> {
        let start_time = std::time::Instant::now();
        
        // Validate request
        self.validate_decryption_request(key_name, ciphertext).await?;
        
        // Perform decryption
        let result = self.engine.decrypt(key_name, ciphertext, context).await;
        
        // Update metrics
        self.update_metrics(|m| {
            m.total_operations_performed += 1;
            if result.is_err() {
                m.api_errors += 1;
            }
        }).await;
        
        match result {
            Ok(plaintext) => Ok(DecryptionResponse {
                plaintext,
                processing_time_ms: start_time.elapsed().as_millis() as u64,
            }),
            Err(e) => Err(e),
        }
    }
    
    /// Process batch operations through the integration layer
    pub async fn batch_operation(
        &self,
        operations: Vec<BatchOperation>,
    ) -> CryptoResult<BatchOperationResponse> {
        let start_time = std::time::Instant::now();
        
        // Validate batch size
        if operations.len() > self.config.api.max_batch_size {
            return Err(CryptoError::ValidationError(
                format!("Batch size {} exceeds maximum {}", 
                       operations.len(), self.config.api.max_batch_size)
            ));
        }
        
        // Process batch
        let results = self.engine.batch_operation(operations).await;
        
        // Update metrics
        let successful = results.iter().filter(|r| r.success).count();
        let failed = results.len() - successful;
        let total_ops = results.len();
        
        self.update_metrics(|m| {
            m.total_operations_performed += total_ops as u64;
            m.api_errors += failed as u64;
        }).await;
        
        Ok(BatchOperationResponse {
            results,
            total_operations: total_ops,
            successful_operations: successful,
            failed_operations: failed,
            processing_time_ms: start_time.elapsed().as_millis() as u64,
        })
    }
    
    /// Validate key creation request
    async fn validate_key_creation(
        &self,
        name: &str,
        key_type: &KeyType,
        _options: &Option<KeyOptions>,
    ) -> CryptoResult<()> {
        if name.is_empty() {
            return Err(CryptoError::ValidationError(
                "Key name cannot be empty".to_string()
            ));
        }
        
        if name.len() > 255 {
            return Err(CryptoError::ValidationError(
                "Key name too long (max 255 characters)".to_string()
            ));
        }
        
        // Validate key type is supported
        match key_type {
            KeyType::Aes256Gcm | KeyType::ChaCha20Poly1305 | KeyType::XChaCha20Poly1305 => Ok(()),
            KeyType::Rsa(size) => {
                if *size < 2048 {
                    Err(CryptoError::ValidationError(
                        "RSA key size must be at least 2048 bits".to_string()
                    ))
                } else {
                    Ok(())
                }
            },
            KeyType::EcdsaP256 | KeyType::EcdsaSecp256k1 | KeyType::Ed25519 | KeyType::X25519 => Ok(()),
        }
    }
    
    /// Validate encryption request
    async fn validate_encryption_request(
        &self,
        key_name: &str,
        plaintext: &[u8],
    ) -> CryptoResult<()> {
        if key_name.is_empty() {
            return Err(CryptoError::ValidationError(
                "Key name cannot be empty".to_string()
            ));
        }
        
        if plaintext.len() > self.config.api.max_request_size {
            return Err(CryptoError::ValidationError(
                format!("Plaintext size {} exceeds maximum {}", 
                       plaintext.len(), self.config.api.max_request_size)
            ));
        }
        
        Ok(())
    }
    
    /// Validate decryption request
    async fn validate_decryption_request(
        &self,
        key_name: &str,
        ciphertext: &str,
    ) -> CryptoResult<()> {
        if key_name.is_empty() {
            return Err(CryptoError::ValidationError(
                "Key name cannot be empty".to_string()
            ));
        }
        
        if ciphertext.len() > self.config.api.max_request_size * 2 {
            return Err(CryptoError::ValidationError(
                "Ciphertext too large".to_string()
            ));
        }
        
        Ok(())
    }
}

/// Response types for integration layer
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyCreationResponse {
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionResponse {
    pub ciphertext: String,
    pub key_version: u32,
    pub processing_time_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptionResponse {
    pub plaintext: Vec<u8>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchOperationResponse {
    pub results: Vec<crate::transit::BatchResult>,
    pub total_operations: usize,
    pub successful_operations: usize,
    pub failed_operations: usize,
    pub processing_time_ms: u64,
}

/// Extension trait for Brankas core integration
pub trait BrankasTransitIntegration {
    /// Add transit engine to Brankas core services
    fn add_transit_engine(&mut self, integration: TransitIntegration) -> CryptoResult<()>;
    
    /// Get transit engine from Brankas core services
    fn get_transit_engine(&self) -> Option<&TransitIntegration>;
    
    /// Configure transit engine endpoints
    fn configure_transit_endpoints(&mut self, config: ApiConfig) -> CryptoResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;
    
    #[tokio::test]
    async fn test_transit_integration() {
        let mut integration = TransitIntegration::new();
        integration.initialize().await.unwrap();
        
        // Test key creation
        let response = integration.create_key(
            "test-key".to_string(),
            KeyType::Aes256Gcm,
            None,
        ).await.unwrap();
        
        assert_eq!(response.name, "test-key");
        
        // Test encryption
        let plaintext = b"test data";
        let encrypt_response = integration.encrypt(
            "test-key",
            plaintext,
            None,
            None,
        ).await.unwrap();
        
        // Test decryption
        let decrypt_response = integration.decrypt(
            "test-key",
            &encrypt_response.ciphertext,
            None,
        ).await.unwrap();
        
        assert_eq!(decrypt_response.plaintext, plaintext);
        
        // Test metrics
        let metrics = integration.get_metrics().await;
        assert_eq!(metrics.total_keys_managed, 1);
        assert_eq!(metrics.total_operations_performed, 2);
    }
    
    #[tokio::test]
    async fn test_validation() {
        let integration = TransitIntegration::new();
        
        // Test empty key name validation
        let result = integration.validate_key_creation("", &KeyType::Aes256Gcm, &None).await;
        assert!(result.is_err());
        
        // Test large plaintext validation
        let large_data = vec![0u8; 2 * 1024 * 1024]; // 2MB
        let result = integration.validate_encryption_request("test-key", &large_data).await;
        assert!(result.is_err());
    }
}
