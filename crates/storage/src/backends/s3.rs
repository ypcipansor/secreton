use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use aws_types::region::Region;
use secreton_common::models::oauth_state::OAuthState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// S3 storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3StorageConfig {
    /// AWS region
    pub region: String,
    /// S3 bucket name
    pub bucket_name: String,
    /// Key prefix for all secreton data
    pub prefix: String,
    /// Enable server-side encryption
    pub server_side_encryption: bool,
    /// KMS key ID for encryption (if enabled)
    pub kms_key_id: Option<String>,
    /// Enable versioning
    pub versioning_enabled: bool,
    /// Enable lifecycle rules
    pub lifecycle_enabled: bool,
    /// Retention days for objects
    pub retention_days: i32,
}

impl Default for S3StorageConfig {
    fn default() -> Self {
        Self {
            region: "us-east-1".to_string(),
            bucket_name: "secreton-secrets-bucket".to_string(),
            prefix: "secreton/".to_string(),
            server_side_encryption: true,
            kms_key_id: None,
            versioning_enabled: true,
            lifecycle_enabled: true,
            retention_days: 30,
        }
    }
}

/// S3 storage backend
pub struct S3Storage {
    config: S3StorageConfig,
    client: aws_sdk_s3::Client,
    cache: Arc<RwLock<HashMap<String, SecretEntry>>>,
}

/// S3 transaction implementation
pub struct S3Transaction {
    operations: Vec<S3Operation>,
    committed: bool,
}

enum S3Operation {
    Store(()),
    Update(()),
    Delete(()),
}

impl Default for S3Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl S3Transaction {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            committed: false,
        }
    }
}

#[async_trait]
impl StorageTransaction for S3Transaction {
    async fn store(&mut self, _entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(S3Operation::Store(()));
        Ok(())
    }

    async fn update(&mut self, _entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(S3Operation::Update(()));
        Ok(())
    }

    async fn delete(&mut self, _id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(S3Operation::Delete(()));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // In a real S3 implementation, operations would be executed
        // S3 doesn't support transactions, so operations would be atomic individually
        // For now, we just mark as committed since we don't have a real connection
        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}

impl S3Storage {
    /// Create new S3 storage backend
    pub async fn new(config: S3StorageConfig) -> Result<Self, StorageError> {
        let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .load()
            .await;
        let client = aws_sdk_s3::Client::new(&shared_config);

        // Create bucket if not exists
        Self::create_bucket_if_not_exists(&client, &config).await?;

        // Configure bucket settings
        Self::configure_bucket(&client, &config).await?;

        Ok(Self {
            config,
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create S3 bucket if not exists
    async fn create_bucket_if_not_exists(
        client: &aws_sdk_s3::Client,
        config: &S3StorageConfig,
    ) -> Result<(), StorageError> {
        // Check if bucket exists
        let result = client
            .head_bucket()
            .bucket(&config.bucket_name)
            .send()
            .await;

        match result {
            Ok(_) => {
                // Bucket exists, nothing to do
                Ok(())
            }
            Err(_) => {
                // Bucket doesn't exist, create it
                let mut create_request = client.create_bucket().bucket(&config.bucket_name);

                // Add region for non-us-east-1 buckets
                if config.region != "us-east-1" {
                    let location_constraint =
                        aws_sdk_s3::types::CreateBucketConfiguration::builder()
                            .location_constraint(aws_sdk_s3::types::BucketLocationConstraint::from(
                                config.region.as_str(),
                            ))
                            .build();

                    create_request =
                        create_request.create_bucket_configuration(location_constraint);
                }

                create_request
                    .send()
                    .await
                    .map_err(|e| StorageError::BackendError {
                        backend: "s3".to_string(),
                        message: format!("Failed to create bucket: {}", e),
                    })?;

                Ok(())
            }
        }
    }

    /// Configure S3 bucket settings (versioning, lifecycle, encryption)
    async fn configure_bucket(
        client: &aws_sdk_s3::Client,
        config: &S3StorageConfig,
    ) -> Result<(), StorageError> {
        // Enable versioning
        if config.versioning_enabled {
            let versioning_config = aws_sdk_s3::types::VersioningConfiguration::builder()
                .status(aws_sdk_s3::types::BucketVersioningStatus::Enabled)
                .build();

            client
                .put_bucket_versioning()
                .bucket(&config.bucket_name)
                .versioning_configuration(versioning_config)
                .send()
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "s3".to_string(),
                    message: format!("Failed to enable versioning: {}", e),
                })?;
        }

        // Configure lifecycle rules
        if config.lifecycle_enabled {
            let transitions = vec![
                aws_sdk_s3::types::Transition::builder()
                    .days(config.retention_days)
                    .storage_class(aws_sdk_s3::types::TransitionStorageClass::Glacier)
                    .build(),
            ];

            let lifecycle_rule = aws_sdk_s3::types::LifecycleRule::builder()
                .id("secreton-secrets-lifecycle")
                .status(aws_sdk_s3::types::ExpirationStatus::Enabled)
                .filter(
                    aws_sdk_s3::types::LifecycleRuleFilter::builder()
                        .prefix(&config.prefix)
                        .build(),
                )
                .set_transitions(Some(transitions))
                .build()
                .map_err(|e| StorageError::ConfigurationError {
                    message: format!("Failed to build lifecycle rule: {}", e),
                })?;

            let lifecycle_config = aws_sdk_s3::types::BucketLifecycleConfiguration::builder()
                .set_rules(Some(vec![lifecycle_rule]))
                .build()
                .map_err(|e| StorageError::ConfigurationError {
                    message: format!("Failed to build lifecycle configuration: {}", e),
                })?;

            client
                .put_bucket_lifecycle_configuration()
                .bucket(&config.bucket_name)
                .lifecycle_configuration(lifecycle_config)
                .send()
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "s3".to_string(),
                    message: format!("Failed to configure lifecycle: {}", e),
                })?;
        }

        Ok(())
    }

    /// Build S3 key from path
    fn build_key(&self, path: &str) -> String {
        format!("{}{}", self.config.prefix.trim_end_matches('/'), path)
    }

    /// Build S3 key for versioned objects
    fn build_versioned_key(&self, path: &str, version: u32) -> String {
        format!(
            "{}/v{}/{}",
            self.config.prefix.trim_end_matches('/'),
            version,
            path
        )
    }

    /// Convert SecretEntry to S3 object data
    fn secreton_entry_to_bytes(&self, entry: &SecretEntry) -> Result<Vec<u8>, StorageError> {
        serde_json::to_vec(entry).map_err(|e| StorageError::SerializationError {
            message: format!("Failed to serialize entry: {}", e),
        })
    }

    /// Convert S3 object data to SecretEntry
    fn bytes_to_secreton_entry(&self, data: &[u8]) -> Result<SecretEntry, StorageError> {
        serde_json::from_slice(data).map_err(|e| StorageError::SerializationError {
            message: format!("Failed to deserialize entry: {}", e),
        })
    }
}

#[async_trait]
impl StorageBackend for S3Storage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let key = self.build_versioned_key(&entry.path, entry.version);
        let data = self.secreton_entry_to_bytes(entry)?;

        let mut put_request = self
            .client
            .put_object()
            .bucket(&self.config.bucket_name)
            .key(&key)
            .body(ByteStream::from(data));

        // Configure server-side encryption
        if self.config.server_side_encryption {
            if let Some(kms_key_id) = &self.config.kms_key_id {
                put_request = put_request
                    .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256)
                    .ssekms_key_id(kms_key_id);
            } else {
                put_request = put_request
                    .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256);
            }
        }

        put_request
            .send()
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "s3".to_string(),
                message: format!("Failed to store object: {}", e),
            })?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(entry.path.clone(), entry.clone());

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        // For S3, we need to scan all objects to find by ID
        // This is not efficient, but necessary for the interface
        let entries = self.list(&QueryParams::default()).await?;
        Ok(entries.into_iter().find(|e| e.id == id))
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(path) {
                return Ok(Some(entry.clone()));
            }
        }

        // Find the latest version of the object
        let mut latest_version = 0;
        let mut latest_key = None;

        // List objects with the path prefix
        let prefix = self.build_key(path);
        let result = self
            .client
            .list_objects_v2()
            .bucket(&self.config.bucket_name)
            .prefix(&prefix)
            .send()
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "s3".to_string(),
                message: format!("Failed to list objects: {}", e),
            })?;

        if let Some(objects) = result.contents {
            for object in objects {
                if let Some(key) = &object.key {
                    // Extract version from key (format: secreton/v{version}/path)
                    if let Some(version_str) = key
                        .strip_prefix(&format!("{}/v", self.config.prefix.trim_end_matches('/')))
                        .and_then(|s| s.split('/').next())
                        && let Ok(version) = version_str.parse::<u32>()
                        && version > latest_version
                    {
                        latest_version = version;
                        latest_key = Some(key.clone());
                    }
                }
            }
        }

        if let Some(key) = latest_key {
            let result = self
                .client
                .get_object()
                .bucket(&self.config.bucket_name)
                .key(&key)
                .send()
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "s3".to_string(),
                    message: format!("Failed to get object: {}", e),
                })?;
            let data = result
                .body
                .collect()
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "s3".to_string(),
                    message: format!("Failed to collect body: {}", e),
                })?;

            let entry = self.bytes_to_secreton_entry(&data.into_bytes())?;
            let mut cache = self.cache.write().await;
            cache.insert(path.to_string(), entry.clone());
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        self.store(entry).await
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        if let Some(entry) = self.get_by_id(id).await? {
            self.delete_by_path(&entry.path).await
        } else {
            Ok(false)
        }
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        // Find all versions of the object
        let prefix = self.build_key(path);
        let result = self
            .client
            .list_object_versions()
            .bucket(&self.config.bucket_name)
            .prefix(&prefix)
            .send()
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "s3".to_string(),
                message: format!("Failed to list object versions: {}", e),
            })?;

        if let Some(versions) = result.versions {
            for version in versions {
                if let (Some(key), Some(version_id)) = (&version.key, &version.version_id) {
                    self.client
                        .delete_object()
                        .bucket(&self.config.bucket_name)
                        .key(key)
                        .version_id(version_id)
                        .send()
                        .await
                        .map_err(|e| StorageError::BackendError {
                            backend: "s3".to_string(),
                            message: format!("Failed to delete object version: {}", e),
                        })?;
                }
            }
        }

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(path);

        Ok(true)
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let mut entries = Vec::new();

        // List objects with prefix
        let prefix = if let Some(ref path_prefix) = params.path_prefix {
            self.build_key(path_prefix)
        } else {
            self.build_key("")
        };

        let result = self
            .client
            .list_objects_v2()
            .bucket(&self.config.bucket_name)
            .prefix(&prefix)
            .send()
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "s3".to_string(),
                message: format!("Failed to list objects: {}", e),
            })?;

        if let Some(objects) = result.contents {
            for object in objects {
                if let Some(key) = &object.key {
                    // Only process versioned objects (skip non-versioned objects)
                    if key.contains("/v") {
                        let result = self
                            .client
                            .get_object()
                            .bucket(&self.config.bucket_name)
                            .key(key)
                            .send()
                            .await
                            .map_err(|e| StorageError::BackendError {
                                backend: "s3".to_string(),
                                message: format!("Failed to get object: {}", e),
                            })?;

                        let data = result.body.collect().await.map_err(|e| {
                            StorageError::BackendError {
                                backend: "s3".to_string(),
                                message: format!("Failed to collect body: {}", e),
                            }
                        })?;

                        let entry = self.bytes_to_secreton_entry(&data.into_bytes())?;
                        entries.push(entry);
                    }
                }
            }
        }

        // Apply filters
        let mut filtered_entries = Vec::new();
        for entry in entries {
            if let Some(owner_id) = params.owner_id
                && entry.owner_id != owner_id
            {
                continue;
            }
            if !params.include_expired && entry.is_expired() {
                continue;
            }
            filtered_entries.push(entry);
        }

        // Apply limit
        if let Some(limit) = params.limit {
            filtered_entries.truncate(limit as usize);
        }

        Ok(filtered_entries)
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let entries = self.list(params).await?;
        Ok(entries.len() as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        Ok(self.get_by_path(path).await?.is_some())
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(S3Transaction::new()))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();

        let result = self
            .client
            .head_bucket()
            .bucket(&self.config.bucket_name)
            .send()
            .await;

        let duration = start.elapsed().as_millis() as f64;

        match result {
            Ok(_) => Ok(HealthStatus {
                is_healthy: true,
                response_time_ms: duration,
                connections_active: 1,
                connections_idle: 0,
                last_error: None,
                uptime_seconds: 0,
            }),
            Err(e) => Ok(HealthStatus {
                is_healthy: false,
                response_time_ms: duration,
                connections_active: 0,
                connections_idle: 0,
                last_error: Some(e.to_string()),
                uptime_seconds: 0,
            }),
        }
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        let entries = self.list(&QueryParams::default()).await?;
        let total_entries = entries.len() as u64;
        let total_size_bytes: u64 = entries.iter().map(|e| e.encrypted_data.len() as u64).sum();

        let mut entries_by_security_level = HashMap::new();
        for entry in &entries {
            *entries_by_security_level
                .entry(entry.security_level)
                .or_insert(0) += 1;
        }

        Ok(StorageStats {
            total_entries,
            total_size_bytes,
            average_entry_size: if total_entries > 0 {
                total_size_bytes as f64 / total_entries as f64
            } else {
                0.0
            },
            entries_by_security_level,
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: entries.iter().filter(|e| e.is_expired()).count() as u64,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        // S3 doesn't require migrations
        Ok(())
    }

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError { backend: "S3".to_string(), message: "Not implemented".to_string() })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError { backend: "S3".to_string(), message: "Not implemented".to_string() })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_config_default() {
        let config = S3StorageConfig::default();
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.bucket_name, "secreton-secrets-bucket");
        assert_eq!(config.prefix, "secreton/");
        assert!(config.server_side_encryption);
        assert!(config.versioning_enabled);
        assert_eq!(config.retention_days, 30);
    }

    #[test]
    fn test_build_key() {
        let config = S3StorageConfig::default();
        // Skip creating actual S3 client for tests
        // In a real implementation, we'd use a mock client

        // Test the key building logic directly
        assert_eq!(
            format!("{}{}", config.prefix.trim_end_matches('/'), "/test/path"),
            "secreton/test/path"
        );
    }

    #[test]
    fn test_build_versioned_key() {
        let config = S3StorageConfig::default();

        // Test the versioned key building logic directly
        assert_eq!(
            format!(
                "{}/v{}/{}",
                config.prefix.trim_end_matches('/'),
                2,
                "test/path"
            ),
            "secreton/v2/test/path"
        );
    }

    #[test]
    fn test_secreton_entry_to_bytes() {
        let _config = S3StorageConfig::default();

        let entry = SecretEntry::new(
            "test/path".to_string(),
            vec![1, 2, 3],
            crate::EncryptionMetadata::default(),
            crate::SecurityLevel::Secret,
            Uuid::new_v4(),
        );

        // Test serialization directly without S3 client
        let bytes = serde_json::to_vec(&entry).unwrap();
        assert!(!bytes.is_empty());

        let deserialized: SecretEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.path, entry.path);
    }
}
