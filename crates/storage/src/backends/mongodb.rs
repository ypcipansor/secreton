use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::{
    Client, Collection, Database,
    bson::{Document, doc},
    options::{ClientOptions, FindOptions, UpdateOptions},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    HealthStatus, QueryParams, SecurityLevel, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction, VaultEntry,
};

/// Configuration for MongoDB storage backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoDBConfig {
    /// MongoDB connection string
    pub connection_string: String,
    /// Database name
    pub database_name: String,
    /// Collection name
    pub collection_name: String,
}

/// MongoDB storage backend implementation
pub struct MongoDBStorage {
    config: MongoDBConfig,
    client: Client,
    database: Database,
    collection: Collection<Document>,
}

/// MongoDB transaction implementation
pub struct MongoDBTransaction {
    operations: Vec<MongoDBOperation>,
    committed: bool,
}

enum MongoDBOperation {
    Store(VaultEntry),
    Update(VaultEntry),
    Delete(Uuid),
}

impl MongoDBTransaction {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            committed: false,
        }
    }
}

#[async_trait]
impl StorageTransaction for MongoDBTransaction {
    async fn store(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(MongoDBOperation::Store(entry.clone()));
        Ok(())
    }

    async fn update(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(MongoDBOperation::Update(entry.clone()));
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(MongoDBOperation::Delete(id));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // In a real MongoDB implementation, you would execute all operations
        // in a transaction using MongoDB's transaction API
        // For now, we just mark as committed since we don't have a real connection
        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}

impl MongoDBStorage {
    /// Create a new MongoDB storage instance
    pub async fn new(config: MongoDBConfig) -> StorageResult<Self> {
        // Parse the connection string
        let client_options = ClientOptions::parse(&config.connection_string)
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to parse connection string: {}", e),
            })?;

        // Create the client
        let client =
            Client::with_options(client_options).map_err(|e| StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to create MongoDB client: {}", e),
            })?;

        // Get the database
        let database = client.database(&config.database_name);

        // Get the collection
        let collection = database.collection::<Document>(&config.collection_name);

        // Test the connection
        database
            .run_command(doc! { "ping": 1 })
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to connect to MongoDB: {}", e),
            })?;

        Ok(Self {
            config,
            client,
            database,
            collection,
        })
    }
}

#[async_trait]
impl StorageBackend for MongoDBStorage {
    async fn store(&self, entry: &VaultEntry) -> StorageResult<()> {
        let data = serde_json::to_string(entry).map_err(|e| StorageError::SerializationError {
            message: format!("Failed to serialize entry: {}", e),
        })?;

        let security_level = match entry.security_level {
            SecurityLevel::Public => "public",
            SecurityLevel::Internal => "internal",
            SecurityLevel::Confidential => "confidential",
            SecurityLevel::Secret => "secret",
            SecurityLevel::TopSecret => "top_secret",
        };

        let metadata: Document = entry
            .metadata
            .iter()
            .map(|(k, v)| (k.clone(), mongodb::bson::Bson::String(v.clone())))
            .collect();

        let tags: Vec<String> = entry.tags.clone();

        let doc = doc! {
            "_id": entry.id.to_string(),
            "path": &entry.path,
            "data": data,
            "security_level": security_level,
            "created_at": entry.created_at.timestamp_millis(),
            "updated_at": entry.updated_at.timestamp_millis(),
            "expires_at": entry.expires_at.map(|dt| dt.timestamp_millis()),
            "owner_id": entry.owner_id.to_string(),
            "metadata": metadata,
            "tags": tags,
        };

        let filter = doc! { "_id": entry.id.to_string() };
        let update = doc! { "$set": doc };

        self.collection
            .update_one(filter, update)
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to store entry: {}", e),
            })?;

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<VaultEntry>> {
        let filter = doc! { "_id": id.to_string() };

        let result =
            self.collection
                .find_one(filter)
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mongodb".to_string(),
                    message: format!("Failed to get entry by ID: {}", e),
                })?;

        if let Some(doc) = result {
            let data: String = doc
                .get_str("data")
                .map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to get data field: {}", e),
                })?
                .to_string();

            let mut entry: VaultEntry =
                serde_json::from_str(&data).map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to deserialize entry: {}", e),
                })?;

            // Override fields from database
            entry.id = id;
            if let Ok(created_at) = doc.get_i64("created_at") {
                entry.created_at =
                    chrono::DateTime::from_timestamp_millis(created_at).unwrap_or(entry.created_at);
            }
            if let Ok(updated_at) = doc.get_i64("updated_at") {
                entry.updated_at =
                    chrono::DateTime::from_timestamp_millis(updated_at).unwrap_or(entry.updated_at);
            }
            if let Ok(expires_at) = doc.get_i64("expires_at") {
                entry.expires_at = chrono::DateTime::from_timestamp_millis(expires_at);
            }

            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<VaultEntry>> {
        let filter = doc! { "path": path };

        let result =
            self.collection
                .find_one(filter)
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mongodb".to_string(),
                    message: format!("Failed to get entry by path: {}", e),
                })?;

        if let Some(doc) = result {
            let data: String = doc
                .get_str("data")
                .map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to get data field: {}", e),
                })?
                .to_string();

            let mut entry: VaultEntry =
                serde_json::from_str(&data).map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to deserialize entry: {}", e),
                })?;

            // Override fields from database
            if let Ok(id_str) = doc.get_str("_id") {
                entry.id = Uuid::parse_str(id_str).unwrap_or(entry.id);
            }
            if let Ok(created_at) = doc.get_i64("created_at") {
                entry.created_at =
                    chrono::DateTime::from_timestamp_millis(created_at).unwrap_or(entry.created_at);
            }
            if let Ok(updated_at) = doc.get_i64("updated_at") {
                entry.updated_at =
                    chrono::DateTime::from_timestamp_millis(updated_at).unwrap_or(entry.updated_at);
            }
            if let Ok(expires_at) = doc.get_i64("expires_at") {
                entry.expires_at = chrono::DateTime::from_timestamp_millis(expires_at);
            }

            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    async fn update(&self, entry: &VaultEntry) -> StorageResult<()> {
        self.store(entry).await
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let filter = doc! { "_id": id.to_string() };

        let result =
            self.collection
                .delete_one(filter)
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mongodb".to_string(),
                    message: format!("Failed to delete entry by ID: {}", e),
                })?;

        Ok(result.deleted_count > 0)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let filter = doc! { "path": path };

        let result =
            self.collection
                .delete_one(filter)
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mongodb".to_string(),
                    message: format!("Failed to delete entry by path: {}", e),
                })?;

        Ok(result.deleted_count > 0)
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<VaultEntry>> {
        let mut filter = Document::new();

        // Add path prefix filter
        if let Some(prefix) = &params.path_prefix {
            filter.insert(
                "path",
                doc! { "$regex": format!("^{}", regex::escape(prefix)) },
            );
        }

        // Add security level filter
        if let Some(min_level) = params.security_level {
            let level_values = match min_level {
                SecurityLevel::Public => {
                    vec!["public", "internal", "confidential", "secret", "top_secret"]
                }
                SecurityLevel::Internal => vec!["internal", "confidential", "secret", "top_secret"],
                SecurityLevel::Confidential => vec!["confidential", "secret", "top_secret"],
                SecurityLevel::Secret => vec!["secret", "top_secret"],
                SecurityLevel::TopSecret => vec!["top_secret"],
            };
            filter.insert("security_level", doc! { "$in": level_values });
        }

        // Add owner filter
        if let Some(owner_id) = params.owner_id {
            filter.insert("owner_id", owner_id.to_string());
        }

        // Add tag filters
        if !params.tags.is_empty() {
            filter.insert("tags", doc! { "$in": params.tags.clone() });
        }

        // Add metadata filters
        if !params.metadata_filters.is_empty() {
            let mut metadata_filter = Document::new();
            for (key, value) in &params.metadata_filters {
                metadata_filter.insert(format!("metadata.{}", key), value);
            }
            filter.insert("$and", vec![metadata_filter]);
        }

        // Exclude expired entries unless requested
        if !params.include_expired {
            let now = chrono::Utc::now().timestamp_millis();
            filter.insert(
                "expires_at",
                doc! { "$or": vec![doc! { "$exists": false }, doc! { "$gt": now }] },
            );
        }

        let mut cursor = self
            .collection
            .find(filter)
            .with_options(
                FindOptions::builder()
                    .limit(params.limit.map(|l| l as i64))
                    .build(),
            )
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to list entries: {}", e),
            })?;

        let mut entries = Vec::new();
        while let Some(result) =
            cursor
                .try_next()
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mongodb".to_string(),
                    message: format!("Failed to iterate results: {}", e),
                })?
        {
            let data: String = result
                .get_str("data")
                .map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to get data field: {}", e),
                })?
                .to_string();

            let mut entry: VaultEntry =
                serde_json::from_str(&data).map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to deserialize entry: {}", e),
                })?;

            // Override fields from database
            if let Ok(id_str) = result.get_str("_id") {
                entry.id = Uuid::parse_str(id_str).unwrap_or(entry.id);
            }
            if let Ok(created_at) = result.get_i64("created_at") {
                entry.created_at =
                    chrono::DateTime::from_timestamp_millis(created_at).unwrap_or(entry.created_at);
            }
            if let Ok(updated_at) = result.get_i64("updated_at") {
                entry.updated_at =
                    chrono::DateTime::from_timestamp_millis(updated_at).unwrap_or(entry.updated_at);
            }
            if let Ok(expires_at) = result.get_i64("expires_at") {
                entry.expires_at = chrono::DateTime::from_timestamp_millis(expires_at);
            }

            entries.push(entry);
        }

        Ok(entries)
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let mut filter = Document::new();

        // Add the same filters as list method
        if let Some(prefix) = &params.path_prefix {
            filter.insert(
                "path",
                doc! { "$regex": format!("^{}", regex::escape(prefix)) },
            );
        }

        if let Some(min_level) = params.security_level {
            let level_values = match min_level {
                SecurityLevel::Public => {
                    vec!["public", "internal", "confidential", "secret", "top_secret"]
                }
                SecurityLevel::Internal => vec!["internal", "confidential", "secret", "top_secret"],
                SecurityLevel::Confidential => vec!["confidential", "secret", "top_secret"],
                SecurityLevel::Secret => vec!["secret", "top_secret"],
                SecurityLevel::TopSecret => vec!["top_secret"],
            };
            filter.insert("security_level", doc! { "$in": level_values });
        }

        if let Some(owner_id) = params.owner_id {
            filter.insert("owner_id", owner_id.to_string());
        }

        if !params.tags.is_empty() {
            filter.insert("tags", doc! { "$in": params.tags.clone() });
        }

        if !params.metadata_filters.is_empty() {
            let mut metadata_filter = Document::new();
            for (key, value) in &params.metadata_filters {
                metadata_filter.insert(format!("metadata.{}", key), value);
            }
            filter.insert("$and", vec![metadata_filter]);
        }

        if !params.include_expired {
            let now = chrono::Utc::now().timestamp_millis();
            filter.insert(
                "expires_at",
                doc! { "$or": vec![doc! { "$exists": false }, doc! { "$gt": now }] },
            );
        }

        let count = self.collection.count_documents(filter).await.map_err(|e| {
            StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to count entries: {}", e),
            }
        })?;

        Ok(count as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let filter = doc! { "path": path };

        let count = self.collection.count_documents(filter).await.map_err(|e| {
            StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to check existence: {}", e),
            }
        })?;

        Ok(count > 0)
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn crate::StorageTransaction>> {
        Ok(Box::new(MongoDBTransaction::new()))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();

        // Test connectivity by running a ping command
        let result = self.database.run_command(doc! { "ping": 1 }).await;

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
                last_error: Some(format!("MongoDB health check failed: {}", e)),
                uptime_seconds: 0,
            }),
        }
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        let total_entries: u64;
        let mut total_size_bytes = 0u64;
        let mut entries_by_security_level = HashMap::new();
        let entries_created_today: u64;
        let entries_updated_today: u64;
        let expired_entries: u64;

        // Get total count
        total_entries = self
            .collection
            .count_documents(Document::new())
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to count total entries: {}", e),
            })? as u64;

        // Get statistics by security level
        let pipeline =
            vec![doc! { "$group": { "_id": "$security_level", "count": { "$sum": 1 } } }];

        let mut cursor =
            self.collection
                .aggregate(pipeline)
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mongodb".to_string(),
                    message: format!("Failed to aggregate by security level: {}", e),
                })?;

        while let Some(result) =
            cursor
                .try_next()
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mongodb".to_string(),
                    message: format!("Failed to iterate aggregation results: {}", e),
                })?
        {
            let level = result.get_str("_id");
            let count = result.get_i64("count");

            if let (Ok(level_str), Ok(count_val)) = (level, count) {
                let security_level = match level_str {
                    "public" => SecurityLevel::Public,
                    "internal" => SecurityLevel::Internal,
                    "confidential" => SecurityLevel::Confidential,
                    "secret" => SecurityLevel::Secret,
                    "top_secret" => SecurityLevel::TopSecret,
                    _ => continue,
                };
                let count_u64 = count_val.max(0) as u64;
                entries_by_security_level.insert(security_level, count_u64);
            }
        }

        // Get entries created today
        let today = chrono::Utc::now().date_naive();
        let start_of_day = today.and_hms_opt(0, 0, 0).unwrap();
        let end_of_day = today.and_hms_opt(23, 59, 59).unwrap();

        let filter = doc! {
            "created_at": {
                "$gte": start_of_day.and_utc().timestamp_millis(),
                "$lte": end_of_day.and_utc().timestamp_millis()
            }
        };
        entries_created_today = self.collection.count_documents(filter).await.map_err(|e| {
            StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to count entries created today: {}", e),
            }
        })? as u64;

        // Get entries updated today
        let filter = doc! {
            "updated_at": {
                "$gte": start_of_day.and_utc().timestamp_millis(),
                "$lte": end_of_day.and_utc().timestamp_millis()
            }
        };
        entries_updated_today = self.collection.count_documents(filter).await.map_err(|e| {
            StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to count entries updated today: {}", e),
            }
        })? as u64;

        // Get expired entries
        let now = chrono::Utc::now().timestamp_millis();
        let filter = doc! { "expires_at": { "$lte": now } };
        expired_entries = self.collection.count_documents(filter).await.map_err(|e| {
            StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to count expired entries: {}", e),
            }
        })? as u64;

        // Calculate average entry size (approximate)
        let pipeline = vec![
            doc! { "$group": { "_id": null, "avg_size": { "$avg": { "$strLenBytes": "$data" } } } },
        ];

        let mut cursor =
            self.collection
                .aggregate(pipeline)
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mongodb".to_string(),
                    message: format!("Failed to calculate average size: {}", e),
                })?;

        if let Some(result) = cursor
            .try_next()
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "mongodb".to_string(),
                message: format!("Failed to get average size result: {}", e),
            })?
        {
            if let Ok(avg_size) = result.get_f64("avg_size") {
                total_size_bytes = (avg_size * total_entries as f64) as u64;
            }
        }

        let average_entry_size = if total_entries > 0 {
            total_size_bytes as f64 / total_entries as f64
        } else {
            0.0
        };

        Ok(StorageStats {
            total_entries,
            total_size_bytes,
            average_entry_size,
            entries_by_security_level,
            entries_created_today,
            entries_updated_today,
            expired_entries,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        // MongoDB migrations would be implemented here
        Ok(())
    }
}

impl Default for MongoDBConfig {
    fn default() -> Self {
        Self {
            connection_string: "mongodb://localhost:27017".to_string(),
            database_name: "vault_kv".to_string(),
            collection_name: "entries".to_string(),
        }
    }
}
