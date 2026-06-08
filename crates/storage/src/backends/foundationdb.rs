//! FoundationDB storage backend for Secreton

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction,
};
use secreton_common::models::oauth_state::OAuthState;

/// FoundationDB storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundationDBConfig {
    pub cluster_file: Option<String>,
}

pub struct FoundationDBStorage {
    #[allow(dead_code)]
    config: FoundationDBConfig,
}

impl FoundationDBStorage {
    pub fn new(config: FoundationDBConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl StorageBackend for FoundationDBStorage {
    async fn store(&self, _entry: &SecretEntry) -> StorageResult<()> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }
    async fn get_by_id(&self, _id: Uuid) -> StorageResult<Option<SecretEntry>> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }
    async fn get_by_path(&self, _path: &str) -> StorageResult<Option<SecretEntry>> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }
    async fn update(&self, _entry: &SecretEntry) -> StorageResult<()> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }
    async fn delete_by_id(&self, _id: Uuid) -> StorageResult<bool> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }
    async fn delete_by_path(&self, _path: &str) -> StorageResult<bool> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }
    async fn list(&self, _params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }
    async fn count(&self, _params: &QueryParams) -> StorageResult<u64> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }
    async fn exists(&self, _path: &str) -> StorageResult<bool> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
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
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError {
            backend: "FoundationDB".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}
