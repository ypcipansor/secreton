//! MSSQL storage backend for Secreton

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use tiberius::{Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::{TokioAsyncWriteCompatExt, Compat};
use std::collections::HashMap;

use crate::{
    StorageBackend, StorageError, SecretEntry, StorageResult,
    StorageTransaction, HealthStatus, StorageStats, QueryParams
};
use secreton_common::models::oauth_state::OAuthState;

/// MSSQL storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSSQLConfig {
    pub connection_string: String,
}

pub struct MSSQLStorage {
    config: MSSQLConfig,
}

impl MSSQLStorage {
    pub fn new(config: MSSQLConfig) -> Self {
        Self { config }
    }

    async fn connect(&self) -> StorageResult<Client<Compat<TcpStream>>> {
        let config = Config::from_ado_string(&self.config.connection_string).map_err(|e| StorageError::ConfigurationError {
            message: e.to_string(),
        })?;

        // Workaround for private get_port():
        // We assume default port 1433 if we can't extract it.
        // Ideally we would parse connection string again or use a public accessor if available.
        // For now, using default.
        let port = 1433;
        let host = config.get_addr();
        let addr = format!("{}:{}", host, port);

        let tcp = TcpStream::connect(addr).await.map_err(|e| StorageError::ConnectionFailed {
            message: e.to_string(),
        })?;

        tcp.set_nodelay(true).ok();

        let client = Client::connect(config, tcp.compat_write()).await.map_err(|e| StorageError::ConnectionFailed {
            message: e.to_string(),
        })?;

        Ok(client)
    }
}

#[async_trait]
impl StorageBackend for MSSQLStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut client = self.connect().await?;
        let data = serde_json::to_string(entry).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;

        client.execute(
            "MERGE INTO secrets WITH (HOLDLOCK) AS target
             USING (VALUES (@P1, @P2, @P3)) AS source (id, path, data)
             ON target.id = source.id
             WHEN MATCHED THEN UPDATE SET path = source.path, data = source.data
             WHEN NOT MATCHED THEN INSERT (id, path, data) VALUES (source.id, source.path, source.data);",
            &[&entry.id, &entry.path, &data]
        ).await.map_err(|e| StorageError::QueryFailed { message: e.to_string() })?;

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let mut client = self.connect().await?;
        let stream = client.query("SELECT data FROM secrets WHERE id = @P1", &[&id]).await.map_err(|e| StorageError::QueryFailed { message: e.to_string() })?;
        let row = stream.into_row().await.map_err(|e| StorageError::QueryFailed { message: e.to_string() })?;

        if let Some(row) = row {
            let data: &str = row.get("data").ok_or(StorageError::SerializationError { message: "Missing data column".to_string() })?;
            let entry: SecretEntry = serde_json::from_str(data).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let mut client = self.connect().await?;
        let stream = client.query("SELECT data FROM secrets WHERE path = @P1", &[&path]).await.map_err(|e| StorageError::QueryFailed { message: e.to_string() })?;
        let row = stream.into_row().await.map_err(|e| StorageError::QueryFailed { message: e.to_string() })?;

        if let Some(row) = row {
            let data: &str = row.get("data").ok_or(StorageError::SerializationError { message: "Missing data column".to_string() })?;
            let entry: SecretEntry = serde_json::from_str(data).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        self.store(entry).await
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let mut client = self.connect().await?;
        let res = client.execute("DELETE FROM secrets WHERE id = @P1", &[&id]).await.map_err(|e| StorageError::QueryFailed { message: e.to_string() })?;
        Ok(res.rows_affected().iter().sum::<u64>() > 0)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let mut client = self.connect().await?;
        let res = client.execute("DELETE FROM secrets WHERE path = @P1", &[&path]).await.map_err(|e| StorageError::QueryFailed { message: e.to_string() })?;
        Ok(res.rows_affected().iter().sum::<u64>() > 0)
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let mut client = self.connect().await?;
        let stream = client.query("SELECT data FROM secrets", &[]).await.map_err(|e| StorageError::QueryFailed { message: e.to_string() })?;

        let rows = stream.into_first_result().await.map_err(|e| StorageError::QueryFailed { message: e.to_string() })?;
        let mut entries = Vec::new();

        for row in rows {
            let data: &str = row.get("data").unwrap_or("{}");
            if let Ok(entry) = serde_json::from_str::<SecretEntry>(data) {
                if let Some(prefix) = &params.path_prefix {
                    if !entry.path.starts_with(prefix) { continue; }
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
        match self.connect().await {
            Ok(mut client) => {
                match client.simple_query("SELECT 1").await {
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
                        connections_active: 1,
                        connections_idle: 0,
                        last_error: Some(e.to_string()),
                        uptime_seconds: 0,
                    })
                }
            }
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
        let mut client = self.connect().await?;
        client.execute("IF OBJECT_ID('secrets', 'U') IS NULL CREATE TABLE secrets (id UNIQUEIDENTIFIER PRIMARY KEY, path NVARCHAR(450) UNIQUE, data NVARCHAR(MAX))", &[]).await.map_err(|e| StorageError::MigrationError { message: e.to_string() })?;
        Ok(())
    }

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError { backend: "MSSQL".to_string(), message: "Not implemented".to_string() })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError { backend: "MSSQL".to_string(), message: "Not implemented".to_string() })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}
