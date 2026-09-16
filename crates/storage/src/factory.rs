//! Construction of a [`StorageBackend`] from configuration.
//!
//! Every variant here maps to a backend that is implemented and tested. The factory used to
//! advertise 24 backends, most of which were unfinished sketches that returned
//! `"Not implemented"` at runtime — an operator could select one from config and only find
//! out in production.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::backends::{FileBackend, MemoryBackend};
use crate::{StorageBackend, StorageError, StorageResult};

/// Which backend to construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackendType {
    /// Process-local, lost on restart. The default so a fresh checkout runs with no setup.
    #[default]
    Memory,
    /// Single-node, durable on local disk.
    File,
    /// Recommended for production.
    #[cfg(feature = "postgres")]
    Postgres,
    #[cfg(feature = "redis")]
    Redis,
    /// Experimental: single-node only, no cluster membership changes yet.
    #[cfg(feature = "raft")]
    Raft,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBackendConfig {
    pub base_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresBackendConfig {
    pub connection_string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisBackendConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftBackendConfig {
    pub data_dir: String,
}

/// Backend selection plus the configuration for the selected backend.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageFactoryConfig {
    #[serde(default)]
    pub backend_type: StorageBackendType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileBackendConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<PostgresBackendConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redis: Option<RedisBackendConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raft: Option<RaftBackendConfig>,
}

fn missing(backend: &str) -> StorageError {
    StorageError::ConfigurationError {
        message: format!("storage backend '{backend}' selected but its configuration is missing"),
    }
}

pub struct StorageFactory;

impl std::fmt::Debug for StorageFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StorageFactory")
    }
}

impl StorageFactory {
    /// Build the configured backend and run its migrations.
    ///
    /// Migrations run here rather than lazily on first use so a misconfigured or
    /// unreachable database fails at startup instead of on a user's first request.
    pub async fn create(
        config: StorageFactoryConfig,
    ) -> StorageResult<Arc<dyn StorageBackend + Send + Sync>> {
        let backend: Arc<dyn StorageBackend + Send + Sync> = match config.backend_type {
            StorageBackendType::Memory => Arc::new(MemoryBackend::new()),

            StorageBackendType::File => {
                let cfg = config.file.ok_or_else(|| missing("file"))?;
                Arc::new(FileBackend::new(&cfg.base_path)?)
            }

            #[cfg(feature = "postgres")]
            StorageBackendType::Postgres => {
                let cfg = config.postgres.ok_or_else(|| missing("postgres"))?;
                Arc::new(crate::backends::PostgresBackend::new(&cfg.connection_string).await?)
            }

            #[cfg(feature = "redis")]
            StorageBackendType::Redis => {
                let cfg = config.redis.ok_or_else(|| missing("redis"))?;
                Arc::new(crate::backends::RedisBackend::new(&cfg.url).await?)
            }

            #[cfg(feature = "raft")]
            StorageBackendType::Raft => {
                let cfg = config.raft.ok_or_else(|| missing("raft"))?;
                let raft_config = crate::backends::RaftConfig {
                    data_dir: cfg.data_dir.into(),
                    ..Default::default()
                };
                Arc::new(crate::backends::RaftStorageBackend::new(raft_config).await?)
            }
        };

        backend.migrate().await?;
        Ok(backend)
    }

    /// In-memory backend, for tests and for a zero-setup first run.
    pub fn memory() -> Arc<dyn StorageBackend + Send + Sync> {
        Arc::new(MemoryBackend::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_is_the_default_and_needs_no_configuration() {
        let backend = StorageFactory::create(StorageFactoryConfig::default())
            .await
            .expect("the default configuration must always construct");
        assert!(backend.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn selecting_a_backend_without_its_config_is_an_error_not_a_panic() {
        let err = StorageFactory::create(StorageFactoryConfig {
            backend_type: StorageBackendType::File,
            ..Default::default()
        })
        .await
        .expect_err("file backend without a path must be rejected");
        assert!(err.to_string().contains("file"), "unhelpful message: {err}");
    }

    #[test]
    fn backend_type_round_trips_through_config_serialisation() {
        let toml = r#"backend_type = "memory""#;
        let cfg: StorageFactoryConfig = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.backend_type, StorageBackendType::Memory);
    }
}
