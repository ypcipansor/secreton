use crate::{
    HealthStatus, QueryParams, StorageBackend, StorageError, StorageResult, StorageStats,
    StorageTransaction, VaultEntry,
};
use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_smithy_types::Blob;
use aws_types::region::Region;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// DynamoDB storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamoDBStorageConfig {
    /// AWS region
    pub region: String,
    /// DynamoDB table name
    pub table_name: String,
    /// Partition key attribute name
    pub partition_key: String,
    /// Sort key attribute name
    pub sort_key: String,
    /// Enable DynamoDB Streams
    pub streams_enabled: bool,
    /// Read capacity units
    pub read_capacity_units: i64,
    /// Write capacity units
    pub write_capacity_units: i64,
    /// Enable auto scaling
    pub auto_scaling_enabled: bool,
    /// Billing mode (PROVISIONED or PAY_PER_REQUEST)
    pub billing_mode: String,
}

impl Default for DynamoDBStorageConfig {
    fn default() -> Self {
        Self {
            region: "us-east-1".to_string(),
            table_name: "vault_kv_store".to_string(),
            partition_key: "path".to_string(),
            sort_key: "version".to_string(),
            streams_enabled: false,
            read_capacity_units: 5,
            write_capacity_units: 5,
            auto_scaling_enabled: false,
            billing_mode: "PROVISIONED".to_string(),
        }
    }
}

/// DynamoDB storage backend
pub struct DynamoDBStorage {
    config: DynamoDBStorageConfig,
    client: aws_sdk_dynamodb::Client,
    cache: Arc<RwLock<HashMap<String, VaultEntry>>>,
}

/// DynamoDB transaction implementation
pub struct DynamoDBTransaction {
    operations: Vec<DynamoDBOperation>,
    committed: bool,
}

enum DynamoDBOperation {
    Store(()),
    Update(()),
    Delete(()),
}

impl DynamoDBTransaction {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            committed: false,
        }
    }
}

#[async_trait]
impl StorageTransaction for DynamoDBTransaction {
    async fn store(&mut self, _entry: &VaultEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(DynamoDBOperation::Store(()));
        Ok(())
    }

    async fn update(&mut self, _entry: &VaultEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(DynamoDBOperation::Update(()));
        Ok(())
    }

    async fn delete(&mut self, _id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(DynamoDBOperation::Delete(()));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // In a real DynamoDB implementation, you would execute all operations
        // in a DynamoDB transaction using TransactWriteItems
        // For now, we just mark as committed since we don't have a real connection
        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}

impl DynamoDBStorage {
    /// Create new DynamoDB storage backend
    pub async fn new(config: DynamoDBStorageConfig) -> Result<Self, StorageError> {
        let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .load()
            .await;

        let client = aws_sdk_dynamodb::Client::new(&shared_config);

        // Create table if not exists
        Self::create_table_if_not_exists(&client, &config).await?;

        Ok(Self {
            config,
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create DynamoDB table if not exists
    async fn create_table_if_not_exists(
        client: &aws_sdk_dynamodb::Client,
        config: &DynamoDBStorageConfig,
    ) -> Result<(), StorageError> {
        // Check if table exists
        let table_result = client
            .describe_table()
            .table_name(&config.table_name)
            .send()
            .await;

        match table_result {
            Ok(_) => {
                // Table exists, nothing to do
                Ok(())
            }
            Err(_) => {
                // Table doesn't exist, create it
                let mut attribute_definitions = Vec::new();
                let ad_pk = aws_sdk_dynamodb::types::AttributeDefinition::builder()
                    .attribute_name(&config.partition_key)
                    .attribute_type(aws_sdk_dynamodb::types::ScalarAttributeType::S)
                    .build()
                    .map_err(|e| StorageError::ConfigurationError {
                        message: format!("Failed to build attribute definition: {}", e),
                    })?;
                attribute_definitions.push(ad_pk);
                let ad_sk = aws_sdk_dynamodb::types::AttributeDefinition::builder()
                    .attribute_name(&config.sort_key)
                    .attribute_type(aws_sdk_dynamodb::types::ScalarAttributeType::N)
                    .build()
                    .map_err(|e| StorageError::ConfigurationError {
                        message: format!("Failed to build attribute definition: {}", e),
                    })?;
                attribute_definitions.push(ad_sk);

                let mut key_schema = Vec::new();
                let ks_hash = aws_sdk_dynamodb::types::KeySchemaElement::builder()
                    .attribute_name(&config.partition_key)
                    .key_type(aws_sdk_dynamodb::types::KeyType::Hash)
                    .build()
                    .map_err(|e| StorageError::ConfigurationError {
                        message: format!("Failed to build key schema: {}", e),
                    })?;
                key_schema.push(ks_hash);
                let ks_range = aws_sdk_dynamodb::types::KeySchemaElement::builder()
                    .attribute_name(&config.sort_key)
                    .key_type(aws_sdk_dynamodb::types::KeyType::Range)
                    .build()
                    .map_err(|e| StorageError::ConfigurationError {
                        message: format!("Failed to build key schema: {}", e),
                    })?;
                key_schema.push(ks_range);

                let mut request = client
                    .create_table()
                    .table_name(&config.table_name)
                    .set_attribute_definitions(Some(attribute_definitions))
                    .set_key_schema(Some(key_schema))
                    .billing_mode(aws_sdk_dynamodb::types::BillingMode::from(
                        config.billing_mode.as_str(),
                    ));

                if config.billing_mode == "PROVISIONED" {
                    let throughput = aws_sdk_dynamodb::types::ProvisionedThroughput::builder()
                        .read_capacity_units(config.read_capacity_units)
                        .write_capacity_units(config.write_capacity_units)
                        .build()
                        .map_err(|e| StorageError::ConfigurationError {
                            message: format!("Failed to build throughput: {}", e),
                        })?;
                    request = request.provisioned_throughput(throughput);
                }

                request
                    .send()
                    .await
                    .map_err(|e| StorageError::BackendError {
                        backend: "dynamodb".to_string(),
                        message: format!("Failed to create table: {}", e),
                    })?;

                // Wait for table to be active
                Self::wait_for_table_active(client, &config.table_name).await?;

                Ok(())
            }
        }
    }

    /// Wait for DynamoDB table to become active
    async fn wait_for_table_active(
        client: &aws_sdk_dynamodb::Client,
        table_name: &str,
    ) -> Result<(), StorageError> {
        loop {
            let result = client
                .describe_table()
                .table_name(table_name)
                .send()
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "dynamodb".to_string(),
                    message: format!("Failed to describe table: {}", e),
                })?;

            if let Some(table) = result.table {
                if let Some(table_status) = table.table_status {
                    if table_status == aws_sdk_dynamodb::types::TableStatus::Active {
                        break;
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }

    /// Convert VaultEntry to DynamoDB item
    fn vault_entry_to_item(&self, entry: &VaultEntry) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();

        item.insert(
            self.config.partition_key.clone(),
            AttributeValue::S(entry.path.clone()),
        );
        item.insert(
            self.config.sort_key.clone(),
            AttributeValue::N(entry.version.to_string()),
        );
        item.insert("id".to_string(), AttributeValue::S(entry.id.to_string()));
        item.insert(
            "encrypted_data".to_string(),
            AttributeValue::B(Blob::new(entry.encrypted_data.clone())),
        );

        let encryption_metadata_json =
            serde_json::to_string(&entry.encryption_metadata).unwrap_or_default();
        item.insert(
            "encryption_metadata".to_string(),
            AttributeValue::S(encryption_metadata_json),
        );

        item.insert(
            "security_level".to_string(),
            AttributeValue::N((entry.security_level as u8).to_string()),
        );

        let metadata_json = serde_json::to_string(&entry.metadata).unwrap_or_default();
        item.insert("metadata".to_string(), AttributeValue::S(metadata_json));

        let tags_json = serde_json::to_string(&entry.tags).unwrap_or_default();
        item.insert("tags".to_string(), AttributeValue::S(tags_json));

        item.insert(
            "owner_id".to_string(),
            AttributeValue::S(entry.owner_id.to_string()),
        );
        item.insert(
            "created_at".to_string(),
            AttributeValue::S(entry.created_at.to_rfc3339()),
        );
        item.insert(
            "updated_at".to_string(),
            AttributeValue::S(entry.updated_at.to_rfc3339()),
        );

        if let Some(expires_at) = entry.expires_at {
            item.insert(
                "expires_at".to_string(),
                AttributeValue::S(expires_at.to_rfc3339()),
            );
        }

        item
    }

    /// Convert DynamoDB item to VaultEntry
    fn item_to_vault_entry(
        &self,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<VaultEntry, StorageError> {
        let path = item
            .get(&self.config.partition_key)
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| StorageError::SerializationError {
                message: format!("Missing {} field", self.config.partition_key),
            })?;

        let version = item
            .get(&self.config.sort_key)
            .and_then(|v| v.as_n().ok())
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| StorageError::SerializationError {
                message: format!("Missing or invalid {} field", self.config.sort_key),
            })?;

        let id = item
            .get("id")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| StorageError::SerializationError {
                message: "Missing or invalid id field".to_string(),
            })?;

        let encrypted_data = item
            .get("encrypted_data")
            .and_then(|v| v.as_b().ok())
            .map(|b| b.as_ref().to_vec())
            .ok_or_else(|| StorageError::SerializationError {
                message: "Missing encrypted_data field".to_string(),
            })?;

        let encryption_metadata_json = item
            .get("encryption_metadata")
            .and_then(|v| v.as_s().ok())
            .map_or("{}", |v| v);

        let encryption_metadata: crate::EncryptionMetadata =
            serde_json::from_str(encryption_metadata_json).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to deserialize encryption metadata: {}", e),
                }
            })?;

        let security_level = item
            .get("security_level")
            .and_then(|v| v.as_n().ok())
            .and_then(|s| s.parse::<u8>().ok())
            .map(|sl| match sl {
                0 => crate::SecurityLevel::Public,
                1 => crate::SecurityLevel::Internal,
                2 => crate::SecurityLevel::Secret,
                3 => crate::SecurityLevel::TopSecret,
                _ => crate::SecurityLevel::Secret,
            })
            .unwrap_or(crate::SecurityLevel::Secret);

        let metadata: Option<HashMap<String, String>> = item
            .get("metadata")
            .and_then(|v| v.as_s().ok())
            .and_then(|json| serde_json::from_str(json).ok());

        let tags = item
            .get("tags")
            .and_then(|v| v.as_s().ok())
            .and_then(|json| serde_json::from_str(json).ok())
            .unwrap_or_default();

        let owner_id = item
            .get("owner_id")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| StorageError::SerializationError {
                message: "Missing or invalid owner_id field".to_string(),
            })?;

        let created_at = item
            .get("created_at")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .ok_or_else(|| StorageError::SerializationError {
                message: "Missing or invalid created_at field".to_string(),
            })?;

        let updated_at = item
            .get("updated_at")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .ok_or_else(|| StorageError::SerializationError {
                message: "Missing or invalid updated_at field".to_string(),
            })?;

        let expires_at = item
            .get("expires_at")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        Ok(VaultEntry {
            id,
            path: path.to_string(),
            encrypted_data,
            encryption_metadata,
            security_level,
            metadata: metadata.unwrap_or_default(),
            tags,
            version,
            owner_id,
            created_at,
            updated_at,
            expires_at,
        })
    }
}

#[async_trait]
impl StorageBackend for DynamoDBStorage {
    async fn store(&self, entry: &VaultEntry) -> StorageResult<()> {
        let item = self.vault_entry_to_item(entry);

        self.client
            .put_item()
            .table_name(&self.config.table_name)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "dynamodb".to_string(),
                message: format!("Failed to store entry: {}", e),
            })?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(entry.path.clone(), entry.clone());

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<VaultEntry>> {
        // For DynamoDB, we need to scan the table to find by ID
        // This is not efficient, but necessary for the interface
        let entries = self.list(&QueryParams::default()).await?;
        Ok(entries.into_iter().find(|e| e.id == id))
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<VaultEntry>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(path) {
                return Ok(Some(entry.clone()));
            }
        }

        let result = self
            .client
            .get_item()
            .table_name(&self.config.table_name)
            .key(
                &self.config.partition_key,
                AttributeValue::S(path.to_string()),
            )
            .send()
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "dynamodb".to_string(),
                message: format!("Failed to get entry: {}", e),
            })?;

        if let Some(item) = result.item {
            let entry = self.item_to_vault_entry(&item)?;
            let mut cache = self.cache.write().await;
            cache.insert(path.to_string(), entry.clone());
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    async fn update(&self, entry: &VaultEntry) -> StorageResult<()> {
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
        let _result = self
            .client
            .delete_item()
            .table_name(&self.config.table_name)
            .key(
                &self.config.partition_key,
                AttributeValue::S(path.to_string()),
            )
            .send()
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "dynamodb".to_string(),
                message: format!("Failed to delete entry: {}", e),
            })?;

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(path);

        Ok(true) // DynamoDB delete_item doesn't return affected rows
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<VaultEntry>> {
        let mut entries = Vec::new();

        // Query by partition key prefix if provided
        if let Some(ref prefix) = params.path_prefix {
            let expression_attribute_values = HashMap::from([(
                ":partitionkeyval".to_string(),
                AttributeValue::S(format!("{}%", prefix)),
            )]);

            let result = self
                .client
                .query()
                .table_name(&self.config.table_name)
                .key_condition_expression("#pk = :partitionkeyval")
                .expression_attribute_names("#pk", &self.config.partition_key)
                .set_expression_attribute_values(Some(expression_attribute_values))
                .send()
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "dynamodb".to_string(),
                    message: format!("Failed to query entries: {}", e),
                })?;

            if let Some(items) = result.items {
                for item in items {
                    let entry = self.item_to_vault_entry(&item)?;
                    entries.push(entry);
                }
            }
        } else {
            // Scan entire table (less efficient but necessary for full list)
            let result = self
                .client
                .scan()
                .table_name(&self.config.table_name)
                .send()
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "dynamodb".to_string(),
                    message: format!("Failed to scan entries: {}", e),
                })?;

            if let Some(items) = result.items {
                for item in items {
                    let entry = self.item_to_vault_entry(&item)?;
                    entries.push(entry);
                }
            }
        }

        // Apply filters
        let mut filtered_entries = Vec::new();
        for entry in entries {
            if let Some(owner_id) = params.owner_id {
                if entry.owner_id != owner_id {
                    continue;
                }
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
        Ok(Box::new(DynamoDBTransaction::new()))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();

        let result = self
            .client
            .describe_table()
            .table_name(&self.config.table_name)
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
        // DynamoDB migrations would be implemented here
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamodb_config_default() {
        let config = DynamoDBStorageConfig::default();
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.table_name, "vault_kv_store");
        assert_eq!(config.partition_key, "path");
        assert_eq!(config.sort_key, "version");
        assert_eq!(config.billing_mode, "PROVISIONED");
    }

    #[test]
    fn test_vault_entry_to_item() {
        let config = DynamoDBStorageConfig::default();
        let storage = DynamoDBStorage {
            config,
            client: aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder().build(),
            ),
            cache: Arc::new(RwLock::new(HashMap::new())),
        };

        let entry = VaultEntry::new(
            "test/path".to_string(),
            vec![1, 2, 3],
            crate::EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "key-1".to_string(),
                iv: vec![0; 12],
                auth_tag: None,
                aad: None,
                kdf_params: None,
            },
            crate::SecurityLevel::Secret,
            Uuid::new_v4(),
        );

        let item = storage.vault_entry_to_item(&entry);
        assert!(item.contains_key("path"));
        assert!(item.contains_key("version"));
        assert!(item.contains_key("encrypted_data"));
    }
}
