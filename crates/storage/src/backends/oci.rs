//! OCI storage backend for Secreton
//!
//! This module provides a OCI-based storage backend implementation.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    StorageBackend, StorageError, SecretEntry, StorageResult,
    StorageTransaction, HealthStatus, StorageStats, QueryParams
};

/// OCI storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCIConfig {
    pub namespace: String,
    pub bucket_name: String,
    pub region: String,
    pub tenancy: String,
    pub user: String,
    pub fingerprint: String,
    pub key_file: String,
}

pub struct OCIStorage {
    #[allow(dead_code)]
    config: OCIConfig,
    #[allow(dead_code)]
    client: Option<Arc<OCIClient>>,
}

struct OCIClient;

impl OCIStorage {
    pub fn new(config: OCIConfig) -> Self {
        Self { config, client: None }
    }
}

#[async_trait]
impl StorageBackend for OCIStorage {
    async fn store(&self, _entry: &SecretEntry) -> StorageResult<()> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }
    async fn get_by_id(&self, _id: Uuid) -> StorageResult<Option<SecretEntry>> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }
    async fn get_by_path(&self, _path: &str) -> StorageResult<Option<SecretEntry>> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }
    async fn update(&self, _entry: &SecretEntry) -> StorageResult<()> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }
    async fn delete_by_id(&self, _id: Uuid) -> StorageResult<bool> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }
    async fn delete_by_path(&self, _path: &str) -> StorageResult<bool> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }
    async fn list(&self, _params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }
    async fn count(&self, _params: &QueryParams) -> StorageResult<u64> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }
    async fn exists(&self, _path: &str) -> StorageResult<bool> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        Ok(HealthStatus {
            is_healthy: false,
            response_time_ms: 0.0,
            connections_active: 0,
            connections_idle: 0,
            last_error: Some("Not implemented".to_string()),
            uptime_seconds: 0,
        })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Err(StorageError::BackendError { backend: "OCI".to_string(), message: "Not implemented".to_string() })
    }
}
