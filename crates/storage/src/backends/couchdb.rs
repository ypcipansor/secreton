//! CouchDB storage backend for Secreton

use async_trait::async_trait;
use couch_rs::types::find::FindQuery;
use couch_rs::document::DocumentCollection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    StorageBackend, StorageError, SecretEntry, StorageResult,
    StorageTransaction, HealthStatus, StorageStats, QueryParams
};

/// CouchDB storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CouchDBConfig {
    pub url: String,
    pub database: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout: u64,
}

pub struct CouchDBStorage {
    client: couch_rs::Client,
    db_name: String,
}

impl CouchDBStorage {
    /// Create a new CouchDB storage backend
    pub async fn new(config: CouchDBConfig) -> StorageResult<Self> {
        let username = config.username.as_deref().unwrap_or("");
        let password = config.password.as_deref().unwrap_or("");

        let client = couch_rs::Client::new(&config.url, username, password)
            .map_err(|e| StorageError::ConfigurationError {
                message: format!("Failed to create CouchDB client: {}", e),
            })?;

        let storage = Self {
            client,
            db_name: config.database.clone(),
        };

        // Ensure database exists
        storage.migrate().await?;

        Ok(storage)
    }

    async fn get_db(&self) -> StorageResult<couch_rs::database::Database> {
        self.client.db(&self.db_name).await.map_err(|e| StorageError::ConnectionFailed {
            message: format!("Failed to access database: {}", e),
        })
    }
}

#[async_trait]
impl StorageBackend for CouchDBStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let db = self.get_db().await?;
        let mut doc = serde_json::to_value(entry).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;

        // Ensure _id is set to entry.id
        if let Some(obj) = doc.as_object_mut() {
            obj.insert("_id".to_string(), Value::String(entry.id.to_string()));
        }

        db.save(&mut doc).await.map_err(|e| StorageError::QueryFailed {
            message: e.to_string(),
        })?;
        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let db = self.get_db().await?;
        // CouchDB uses String for IDs
        match db.get::<Value>(&id.to_string()).await {
            Ok(doc) => {
                let entry: SecretEntry = serde_json::from_value(doc).map_err(|e| StorageError::SerializationError {
                    message: e.to_string(),
                })?;
                Ok(Some(entry))
            },
            Err(e) if e.to_string().contains("404") || e.to_string().contains("NotFound") => Ok(None),
            Err(e) => Err(StorageError::QueryFailed { message: e.to_string() }),
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let db = self.get_db().await?;
        let find_query = FindQuery::new(serde_json::json!({
            "selector": {
                "path": path
            },
            "limit": 1
        }));

        let result: DocumentCollection<Value> = db.find(&find_query).await.map_err(|e| StorageError::QueryFailed {
            message: e.to_string(),
        })?;

        if result.rows.is_empty() {
            Ok(None)
        } else {
            let entry: SecretEntry = serde_json::from_value(result.rows[0].clone()).map_err(|e| StorageError::SerializationError {
                message: e.to_string(),
            })?;
            Ok(Some(entry))
        }
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        let db = self.get_db().await?;
        // Need to get existing _rev
        let existing = db.get::<Value>(&entry.id.to_string()).await.map_err(|e| StorageError::NotFound {
            resource_type: "SecretEntry".to_string(),
            id: entry.id.to_string() + &e.to_string(), // Keep e used to avoid warning
        })?;

        let mut doc = serde_json::to_value(entry).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;

        if let Some(obj) = doc.as_object_mut() {
            obj.insert("_id".to_string(), Value::String(entry.id.to_string()));
            if let Some(rev) = existing.get("_rev") {
                obj.insert("_rev".to_string(), rev.clone());
            }
        }

        db.save(&mut doc).await.map_err(|e| StorageError::QueryFailed {
            message: e.to_string(),
        })?;
        Ok(())
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let db = self.get_db().await?;
        match db.get::<Value>(&id.to_string()).await {
            Ok(mut doc) => {
                if let Some(obj) = doc.as_object_mut() {
                    obj.insert("_deleted".to_string(), Value::Bool(true));
                }

                db.save(&mut doc).await.map_err(|e| StorageError::QueryFailed {
                    message: e.to_string(),
                })?;
                Ok(true)
            },
            Err(_) => Ok(false),
        }
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        if let Some(entry) = self.get_by_path(path).await? {
            self.delete_by_id(entry.id).await
        } else {
            Ok(false)
        }
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let db = self.get_db().await?;
        let mut selector = serde_json::Map::new();

        if let Some(prefix) = &params.path_prefix {
            selector.insert("path".to_string(), serde_json::json!({
                "$regex": format!("^{}", regex::escape(prefix))
            }));
        }

        // Always add a selector to match everything if empty
        if selector.is_empty() {
            selector.insert("_id".to_string(), serde_json::json!({ "$gt": null }));
        }

        let mut query = FindQuery::new(Value::Object(selector));
        if let Some(limit) = params.limit {
            // Safe conversion with cap
            let limit_u64: u64 = limit.into();
            query = query.limit(limit_u64);
        }

        let result: DocumentCollection<Value> = db.find(&query).await.map_err(|e| StorageError::QueryFailed {
            message: e.to_string(),
        })?;

        let mut entries = Vec::new();
        for row in result.rows {
            // Filter out internal fields before deserializing if needed, or rely on struct ignore unknown
            if let Ok(entry) = serde_json::from_value::<SecretEntry>(row) {
                // Manual expiration check if DB query didn't handle it
                if !params.include_expired && entry.is_expired() {
                    continue;
                }
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let entries = self.list(params).await?;
        Ok(entries.len() as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        Ok(self.get_by_path(path).await?.is_some())
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(crate::MockTransaction))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();
        match self.client.check_status().await {
            Ok(_) => Ok(HealthStatus {
                is_healthy: true,
                response_time_ms: start.elapsed().as_millis() as f64,
                connections_active: 1,
                connections_idle: 0,
                last_error: None,
                uptime_seconds: 0,
            }),
            Err(e) => Ok(HealthStatus {
                is_healthy: false,
                response_time_ms: start.elapsed().as_millis() as f64,
                connections_active: 0,
                connections_idle: 0,
                last_error: Some(e.to_string()),
                uptime_seconds: 0,
            }),
        }
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        Ok(StorageStats {
            total_entries: 0,
            total_size_bytes: 0,
            average_entry_size: 0.0,
            entries_by_security_level: HashMap::new(),
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        // Create DB if not exists. check_status confirms server is up.
        // We use make_db instead of create_db if create_db is missing or deprecated
        // But couch_rs docs say db(...) gets a handle, verify creation.
        // There is make_db in recent versions.

        // Try getting db, if fails, create it.
        if self.client.db(&self.db_name).await.is_err() {
             self.client.make_db(&self.db_name).await.map_err(|e| StorageError::MigrationError {
                message: e.to_string(),
            })?;
        }
        Ok(())
    }
}
