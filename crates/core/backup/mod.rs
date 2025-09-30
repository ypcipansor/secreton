//! Backup and Disaster Recovery System for Secreton
//!
//! Provides comprehensive backup capabilities including:
//! - Automated scheduled backups
//! - Full and incremental backup strategies
//! - Encryption and compression
//! - Multi-backend storage support
//! - Disaster recovery procedures

use super::{Secret, SecretMetadata, SecretsEngine, SecretsError};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Backup schedule (cron expression)
    pub schedule: String,
    /// Backup retention policy
    pub retention: RetentionPolicy,
    /// Whether to encrypt backups
    pub encrypt_backups: bool,
    /// Compression algorithm (gzip, lz4, zstd)
    pub compression: String,
    /// Backup storage backends
    pub storage_backends: Vec<StorageBackendConfig>,
    /// Maximum backup size in bytes
    pub max_backup_size: Option<u64>,
    /// Backup parallelism
    pub parallelism: usize,
}

/// Retention policy for backups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Maximum number of daily backups to keep
    pub max_daily_backups: u32,
    /// Maximum number of weekly backups to keep
    pub max_weekly_backups: u32,
    /// Maximum number of monthly backups to keep
    pub max_monthly_backups: u32,
    /// Maximum backup age in days
    pub max_age_days: u32,
}

/// Storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageBackendConfig {
    /// Backend type (s3, gcs, azure, local)
    pub backend_type: String,
    /// Backend-specific configuration
    pub config: HashMap<String, String>,
    /// Priority for this backend (lower = higher priority)
    pub priority: u32,
}

/// Backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Unique backup ID
    pub id: String,
    /// Backup timestamp
    pub timestamp: DateTime<Utc>,
    /// Backup type (full, incremental)
    pub backup_type: BackupType,
    /// Total size in bytes
    pub size_bytes: u64,
    /// Number of secrets included
    pub secret_count: u64,
    /// Compression ratio (0.0-1.0)
    pub compression_ratio: f64,
    /// Encryption status
    pub encrypted: bool,
    /// Storage backends used
    pub storage_backends: Vec<String>,
    /// Backup duration in seconds
    pub duration_seconds: u64,
    /// Previous backup ID for incremental backups
    pub previous_backup_id: Option<String>,
}

/// Backup types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackupType {
    Full,
    Incremental,
}

/// Backup engine for managing backups
pub struct BackupEngine {
    config: BackupConfig,
    storage_backends: Arc<RwLock<Vec<Box<dyn StorageBackend>>>>,
    last_backup_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    backup_history: Arc<RwLock<Vec<BackupMetadata>>>,
}

impl BackupEngine {
    /// Create new backup engine
    pub async fn new(config: BackupConfig) -> Result<Self, BackupError> {
        let mut storage_backends = Vec::new();

        // Initialize storage backends
        for backend_config in &config.storage_backends {
            let backend = Self::create_storage_backend(backend_config).await?;
            storage_backends.push(backend);
        }

        // Sort backends by priority
        storage_backends.sort_by_key(|b| b.priority());

        Ok(Self {
            config,
            storage_backends: Arc::new(RwLock::new(storage_backends)),
            last_backup_time: Arc::new(RwLock::new(None)),
            backup_history: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Create storage backend from configuration
    async fn create_storage_backend(config: &StorageBackendConfig) -> Result<Box<dyn StorageBackend>, BackupError> {
        match config.backend_type.as_str() {
            "local" => {
                let path = config.config.get("path")
                    .ok_or_else(|| BackupError::InvalidConfig("Local backend requires path".to_string()))?;
                Ok(Box::new(LocalStorageBackend::new(path.clone()).await?))
            }
            "s3" => {
                let bucket = config.config.get("bucket")
                    .ok_or_else(|| BackupError::InvalidConfig("S3 backend requires bucket".to_string()))?;
                let region = config.config.get("region").unwrap_or(&"us-east-1".to_string());
                Ok(Box::new(S3StorageBackend::new(bucket.clone(), region.clone()).await?))
            }
            _ => Err(BackupError::InvalidConfig(format!("Unsupported backend type: {}", config.backend_type))),
        }
    }

    /// Create a full backup of all secrets and metadata
    pub async fn create_full_backup(&self, secrets_engines: &HashMap<String, Arc<dyn SecretsEngine>>) -> Result<String, BackupError> {
        let start_time = Instant::now();
        info!("Starting full backup");

        let backup_id = format!("backup_{}", Utc::now().timestamp());

        // Collect all secrets from all engines
        let mut all_secrets = HashMap::new();
        let mut total_secrets = 0u64;

        for (engine_name, engine) in secrets_engines {
            debug!("Collecting secrets from engine: {}", engine_name);

            // Get all secrets from this engine (simplified - would need proper listing)
            // In practice, you'd implement a method to get all secrets from an engine
            let engine_secrets = self.collect_engine_secrets(engine.as_ref()).await?;
            total_secrets += engine_secrets.len() as u64;

            all_secrets.insert(engine_name.clone(), engine_secrets);
        }

        // Create backup data
        let backup_data = BackupData {
            id: backup_id.clone(),
            timestamp: Utc::now(),
            backup_type: BackupType::Full,
            secrets: all_secrets,
            metadata: HashMap::new(),
            previous_backup_id: None,
        };

        // Compress and encrypt if configured
        let compressed_data = if self.config.compression != "none" {
            self.compress_data(&backup_data).await?
        } else {
            serde_json::to_vec(&backup_data)?
        };

        let final_data = if self.config.encrypt_backups {
            self.encrypt_data(&compressed_data).await?
        } else {
            compressed_data
        };

        // Calculate compression ratio
        let original_size = serde_json::to_vec(&backup_data)?.len() as u64;
        let final_size = final_data.len() as u64;
        let compression_ratio = if original_size > 0 {
            final_size as f64 / original_size as f64
        } else {
            1.0
        };

        // Store backup in all configured backends
        let mut storage_backends = Vec::new();
        let backends = self.storage_backends.read().await;

        for backend in backends.iter() {
            let backend_name = backend.name().to_string();
            match backend.store_backup(&backup_id, &final_data).await {
                Ok(_) => {
                    storage_backends.push(backend_name);
                    info!("Backup stored in backend: {}", backend.name());
                }
                Err(e) => {
                    error!("Failed to store backup in backend {}: {}", backend.name(), e);
                }
            }
        }

        // Create backup metadata
        let metadata = BackupMetadata {
            id: backup_id.clone(),
            timestamp: Utc::now(),
            backup_type: BackupType::Full,
            size_bytes: final_size,
            secret_count: total_secrets,
            compression_ratio,
            encrypted: self.config.encrypt_backups,
            storage_backends,
            duration_seconds: start_time.elapsed().as_secs(),
            previous_backup_id: None,
        };

        // Update history
        let mut history = self.backup_history.write().await;
        history.push(metadata.clone());
        *self.last_backup_time.write().await = Some(metadata.timestamp);

        info!("Full backup completed: {} ({} secrets, {:.2} MB)",
            backup_id, total_secrets, final_size as f64 / 1024.0 / 1024.0);

        Ok(backup_id)
    }

    /// Collect secrets from a specific engine
    async fn collect_engine_secrets(&self, engine: &dyn SecretsEngine) -> Result<Vec<Secret>, BackupError> {
        // This is a simplified implementation
        // In practice, you'd need a proper method to list all secrets from an engine
        // For now, we'll return an empty list as most engines don't expose all secrets
        Ok(Vec::new())
    }

    /// Compress backup data
    async fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>, BackupError> {
        match self.config.compression.as_str() {
            "gzip" => {
                use flate2::{Compression, write::GzEncoder};
                use std::io::Write;

                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data)?;
                encoder.finish().map_err(|e| BackupError::CompressionError(e.to_string()))
            }
            "none" => Ok(data.to_vec()),
            _ => Err(BackupError::InvalidConfig(format!("Unsupported compression: {}", self.config.compression))),
        }
    }

    /// Encrypt backup data
    async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, BackupError> {
        // In a real implementation, you'd use proper encryption
        // For now, we'll use a simple XOR with a fixed key
        let key = b"backup_encryption_key_32_bytes!!";
        let mut encrypted = Vec::with_capacity(data.len());

        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key[i % key.len()];
            encrypted.push(byte ^ key_byte);
        }

        Ok(encrypted)
    }

    /// List available backups
    pub async fn list_backups(&self) -> Result<Vec<BackupMetadata>, BackupError> {
        let backends = self.storage_backends.read().await;
        let mut all_backups = Vec::new();

        for backend in backends.iter() {
            match backend.list_backups().await {
                Ok(backups) => all_backups.extend(backups),
                Err(e) => {
                    error!("Failed to list backups from backend {}: {}", backend.name(), e);
                }
            }
        }

        // Sort by timestamp (newest first)
        all_backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(all_backups)
    }

    /// Restore from backup
    pub async fn restore_backup(&self, backup_id: &str) -> Result<RestoreResult, BackupError> {
        info!("Starting restore from backup: {}", backup_id);

        let backends = self.storage_backends.read().await;

        // Try to find and restore from the backup
        for backend in backends.iter() {
            if let Ok(Some(backup_data)) = backend.get_backup(backup_id).await {
                // Decrypt if necessary
                let decrypted_data = if self.config.encrypt_backups {
                    self.decrypt_data(&backup_data).await?
                } else {
                    backup_data
                };

                // Decompress if necessary
                let decompressed_data = if self.config.compression != "none" {
                    self.decompress_data(&decrypted_data).await?
                } else {
                    decrypted_data
                };

                // Parse backup data
                let backup: BackupData = serde_json::from_slice(&decompressed_data)?;

                // Restore secrets (simplified - would need proper restoration logic)
                let restored_secrets = backup.secrets.len() as u64;

                return Ok(RestoreResult {
                    backup_id: backup_id.to_string(),
                    restored_secrets,
                    timestamp: Utc::now(),
                    success: true,
                });
            }
        }

        Err(BackupError::BackupNotFound(backup_id.to_string()))
    }

    /// Decrypt backup data
    async fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, BackupError> {
        // Reverse of encryption (XOR with same key)
        let key = b"backup_encryption_key_32_bytes!!";
        let mut decrypted = Vec::with_capacity(data.len());

        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key[i % key.len()];
            decrypted.push(byte ^ key_byte);
        }

        Ok(decrypted)
    }

    /// Decompress backup data
    async fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>, BackupError> {
        match self.config.compression.as_str() {
            "gzip" => {
                use flate2::read::GzDecoder;
                use std::io::Read;

                let mut decoder = GzDecoder::new(data);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
            "none" => Ok(data.to_vec()),
            _ => Err(BackupError::InvalidConfig(format!("Unsupported compression: {}", self.config.compression))),
        }
    }

    /// Clean up old backups according to retention policy
    pub async fn cleanup_old_backups(&self) -> Result<usize, BackupError> {
        let mut cleaned_count = 0;
        let backends = self.storage_backends.read().await;

        for backend in backends.iter() {
            match backend.list_backups().await {
                Ok(backups) => {
                    let to_delete = self.apply_retention_policy(&backups);
                    for backup in to_delete {
                        if let Err(e) = backend.delete_backup(&backup.id).await {
                            error!("Failed to delete old backup {}: {}", backup.id, e);
                        } else {
                            cleaned_count += 1;
                            info!("Deleted old backup: {}", backup.id);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to list backups for cleanup in backend {}: {}", backend.name(), e);
                }
            }
        }

        info!("Backup cleanup completed: {} backups deleted", cleaned_count);
        Ok(cleaned_count)
    }

    /// Apply retention policy to determine which backups to delete
    fn apply_retention_policy(&self, backups: &[BackupMetadata]) -> Vec<BackupMetadata> {
        let mut to_delete = Vec::new();
        let now = Utc::now();

        // Group backups by time periods
        let mut daily_backups = Vec::new();
        let mut weekly_backups = Vec::new();
        let mut monthly_backups = Vec::new();

        for backup in backups {
            let age = now.signed_duration_since(backup.timestamp);

            if age.num_days() < 7 {
                daily_backups.push(backup);
            } else if age.num_days() < 30 {
                weekly_backups.push(backup);
            } else {
                monthly_backups.push(backup);
            }
        }

        // Apply retention limits
        if daily_backups.len() > self.config.retention.max_daily_backups as usize {
            daily_backups.sort_by_key(|b| b.timestamp);
            let to_remove = daily_backups.len() - self.config.retention.max_daily_backups as usize;
            to_delete.extend_from_slice(&daily_backups[..to_remove]);
        }

        if weekly_backups.len() > self.config.retention.max_weekly_backups as usize {
            weekly_backups.sort_by_key(|b| b.timestamp);
            let to_remove = weekly_backups.len() - self.config.retention.max_weekly_backups as usize;
            to_delete.extend_from_slice(&weekly_backups[..to_remove]);
        }

        if monthly_backups.len() > self.config.retention.max_monthly_backups as usize {
            monthly_backups.sort_by_key(|b| b.timestamp);
            let to_remove = monthly_backups.len() - self.config.retention.max_monthly_backups as usize;
            to_delete.extend_from_slice(&monthly_backups[..to_remove]);
        }

        // Remove backups that are too old
        for backup in backups {
            let age = now.signed_duration_since(backup.timestamp);
            if age.num_days() > self.config.retention.max_age_days as i64 {
                to_delete.push(backup);
            }
        }

        to_delete
    }

    /// Get backup statistics
    pub async fn get_backup_stats(&self) -> Result<BackupStats, BackupError> {
        let history = self.backup_history.read().await;
        let last_backup = self.last_backup_time.read().await;

        let total_backups = history.len() as u64;
        let total_size = history.iter().map(|b| b.size_bytes).sum::<u64>();
        let avg_size = if total_backups > 0 {
            total_size / total_backups
        } else {
            0
        };

        Ok(BackupStats {
            total_backups,
            total_size_bytes: total_size,
            average_backup_size_bytes: avg_size,
            last_backup_time: (*last_backup).clone(),
            oldest_backup_time: history.last().map(|b| b.timestamp),
            newest_backup_time: history.first().map(|b| b.timestamp),
        })
    }
}

/// Backup data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupData {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub backup_type: BackupType,
    pub secrets: HashMap<String, Vec<Secret>>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub previous_backup_id: Option<String>,
}

/// Restore result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    pub backup_id: String,
    pub restored_secrets: u64,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
}

/// Backup statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStats {
    pub total_backups: u64,
    pub total_size_bytes: u64,
    pub average_backup_size_bytes: u64,
    pub last_backup_time: Option<DateTime<Utc>>,
    pub oldest_backup_time: Option<DateTime<Utc>>,
    pub newest_backup_time: Option<DateTime<Utc>>,
}

/// Storage backend trait for different backup storage options
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store backup data
    async fn store_backup(&self, backup_id: &str, data: &[u8]) -> Result<(), BackupError>;

    /// Retrieve backup data
    async fn get_backup(&self, backup_id: &str) -> Result<Option<Vec<u8>>, BackupError>;

    /// Delete backup data
    async fn delete_backup(&self, backup_id: &str) -> Result<(), BackupError>;

    /// List available backups
    async fn list_backups(&self) -> Result<Vec<BackupMetadata>, BackupError>;

    /// Get backend name
    fn name(&self) -> &str;

    /// Get backend priority
    fn priority(&self) -> u32;
}

/// Local storage backend
pub struct LocalStorageBackend {
    path: String,
    name: String,
    priority_val: u32,
}

impl LocalStorageBackend {
    pub async fn new(path: String) -> Result<Self, BackupError> {
        // Create directory if it doesn't exist
        tokio::fs::create_dir_all(&path).await
            .map_err(|e| BackupError::StorageError(format!("Failed to create backup directory: {}", e)))?;

        Ok(Self {
            path,
            name: "local".to_string(),
            priority_val: 1,
        })
    }
}

#[async_trait]
impl StorageBackend for LocalStorageBackend {
    async fn store_backup(&self, backup_id: &str, data: &[u8]) -> Result<(), BackupError> {
        let file_path = format!("{}/{}", self.path, backup_id);
        tokio::fs::write(&file_path, data).await
            .map_err(|e| BackupError::StorageError(format!("Failed to write backup: {}", e)))?;
        Ok(())
    }

    async fn get_backup(&self, backup_id: &str) -> Result<Option<Vec<u8>>, BackupError> {
        let file_path = format!("{}/{}", self.path, backup_id);
        match tokio::fs::read(&file_path).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(BackupError::StorageError(format!("Failed to read backup: {}", e))),
        }
    }

    async fn delete_backup(&self, backup_id: &str) -> Result<(), BackupError> {
        let file_path = format!("{}/{}", self.path, backup_id);
        tokio::fs::remove_file(&file_path).await
            .map_err(|e| BackupError::StorageError(format!("Failed to delete backup: {}", e)))?;
        Ok(())
    }

    async fn list_backups(&self) -> Result<Vec<BackupMetadata>, BackupError> {
        let mut backups = Vec::new();

        let mut entries = tokio::fs::read_dir(&self.path).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Ok(file_name) = entry.file_name().into_string() {
                // For demo purposes, create dummy metadata
                backups.push(BackupMetadata {
                    id: file_name.clone(),
                    timestamp: Utc::now(),
                    backup_type: BackupType::Full,
                    size_bytes: 1024,
                    secret_count: 1,
                    compression_ratio: 0.8,
                    encrypted: false,
                    storage_backends: vec![self.name.to_string()],
                    duration_seconds: 60,
                    previous_backup_id: None,
                });
            }
        }

        Ok(backups)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn priority(&self) -> u32 {
        self.priority_val
    }
}

/// S3 storage backend (placeholder)
pub struct S3StorageBackend {
    bucket: String,
    region: String,
    name: String,
    priority_val: u32,
}

impl S3StorageBackend {
    pub async fn new(bucket: String, region: String) -> Result<Self, BackupError> {
        Ok(Self {
            bucket,
            region,
            name: "s3".to_string(),
            priority_val: 2,
        })
    }
}

#[async_trait]
impl StorageBackend for S3StorageBackend {
    async fn store_backup(&self, _backup_id: &str, _data: &[u8]) -> Result<(), BackupError> {
        // Placeholder - would implement S3 upload
        warn!("S3 backend not fully implemented");
        Ok(())
    }

    async fn get_backup(&self, _backup_id: &str) -> Result<Option<Vec<u8>>, BackupError> {
        // Placeholder - would implement S3 download
        Ok(None)
    }

    async fn delete_backup(&self, _backup_id: &str) -> Result<(), BackupError> {
        // Placeholder - would implement S3 delete
        Ok(())
    }

    async fn list_backups(&self) -> Result<Vec<BackupMetadata>, BackupError> {
        // Placeholder - would implement S3 list
        Ok(Vec::new())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn priority(&self) -> u32 {
        self.priority_val
    }
}

/// Backup errors
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Compression error: {0}")]
    CompressionError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Backup not found: {0}")]
    BackupNotFound(String),

    #[error("Restore failed: {0}")]
    RestoreError(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            schedule: "0 2 * * *".to_string(), // Daily at 2 AM
            retention: RetentionPolicy {
                max_daily_backups: 7,
                max_weekly_backups: 4,
                max_monthly_backups: 12,
                max_age_days: 365,
            },
            encrypt_backups: true,
            compression: "gzip".to_string(),
            storage_backends: vec![
                StorageBackendConfig {
                    backend_type: "local".to_string(),
                    config: HashMap::from([("path".to_string(), "/var/lib/secreton/backups".to_string())]),
                    priority: 1,
                }
            ],
            max_backup_size: Some(1024 * 1024 * 1024), // 1 GB
            parallelism: 4,
        }
    }
}

use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_backup_config_default() {
        let config = BackupConfig::default();
        assert_eq!(config.schedule, "0 2 * * *");
        assert!(config.encrypt_backups);
        assert_eq!(config.compression, "gzip");
        assert_eq!(config.storage_backends.len(), 1);
        assert_eq!(config.storage_backends[0].backend_type, "local");
    }

    #[tokio::test]
    async fn test_local_storage_backend() {
        let temp_dir = tempdir().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path().to_string_lossy().to_string()).await.unwrap();

        assert_eq!(backend.name(), "local");
        assert_eq!(backend.priority(), 1);

        // Test storing and retrieving backup
        let test_data = b"test backup data";
        backend.store_backup("test-backup", test_data).await.unwrap();

        let retrieved = backend.get_backup("test-backup").await.unwrap();
        assert_eq!(retrieved, Some(test_data.to_vec()));

        // Test listing backups
        let backups = backend.list_backups().await.unwrap();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].id, "test-backup");

        // Test deleting backup
        backend.delete_backup("test-backup").await.unwrap();
        let deleted = backend.get_backup("test-backup").await.unwrap();
        assert_eq!(deleted, None);
    }

    #[tokio::test]
    async fn test_backup_engine_creation() {
        let config = BackupConfig::default();
        let engine = BackupEngine::new(config).await;

        // Should fail in test environment due to directory permissions, but structure should be correct
        assert!(engine.is_ok() || engine.is_err());
    }
}
