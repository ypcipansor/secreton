//! Audit log storage backends

use super::*;
use async_trait::async_trait;
use std::path::Path;

#[cfg(feature = "postgres")]
use deadpool_postgres::Pool;

/// PostgreSQL backend for audit logs
#[cfg(feature = "postgres")]
pub struct PostgreSqlBackend {
    pool: Pool,
}

#[cfg(feature = "postgres")]
impl PostgreSqlBackend {
    /// Create a new PostgreSQL backend
    pub async fn new(pool: Pool) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create audit logs table if it doesn't exist
        let client = pool.get().await?;
        client
            .execute(
                "CREATE TABLE IF NOT EXISTS audit_logs (
                    id UUID PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    action TEXT NOT NULL,
                    actor_id TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    status TEXT NOT NULL,
                    ip TEXT,
                    user_agent TEXT,
                    metadata JSONB
                )",
                &[],
            )
            .await?;

        Ok(Self { pool })
    }
}

#[async_trait]
#[cfg(feature = "postgres")]
impl AuditBackend for PostgreSqlBackend {
    async fn log(&self, entry: AuditLog) -> Result<(), AuditError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| AuditError::LoggingError(e.to_string()))?;

        let metadata = serde_json::to_string(&entry.metadata)
            .map_err(|e| AuditError::LoggingError(e.to_string()))?;

        client
            .execute(
                "INSERT INTO audit_logs (
                id, timestamp, action, actor_id, resource_type,
                resource_id, status, ip, user_agent, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[
                    &entry.id,
                    &entry.timestamp,
                    &entry.action,
                    &entry.actor,
                    &entry.resource_type,
                    &entry.resource_id,
                    &match entry.status {
                        AuditStatus::Success => "success",
                        AuditStatus::Failure => "failure",
                        AuditStatus::Denied => "denied",
                    },
                    &entry.ip,
                    &entry.user_agent,
                    &metadata,
                ],
            )
            .await
            .map_err(|e| AuditError::LoggingError(e.to_string()))?;

        Ok(())
    }
}

/// Console backend for development
pub struct ConsoleBackend;

#[async_trait]
impl AuditBackend for ConsoleBackend {
    async fn log(&self, entry: AuditLog) -> Result<(), AuditError> {
        println!("[AUDIT] {:?}", entry);
        Ok(())
    }
}

/// File-based backend
pub struct FileBackend {
    file: tokio::sync::Mutex<tokio::fs::File>,
}

impl FileBackend {
    /// Create a new file backend
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        Ok(Self {
            file: tokio::sync::Mutex::new(file),
        })
    }
}

#[async_trait]
impl AuditBackend for FileBackend {
    async fn log(&self, entry: AuditLog) -> Result<(), AuditError> {
        let mut file = self.file.lock().await;
        let line =
            serde_json::to_string(&entry).map_err(|e| AuditError::LoggingError(e.to_string()))?;

        use tokio::io::AsyncWriteExt;
        file.write_all(line.as_bytes())
            .await
            .map_err(|e| AuditError::LoggingError(e.to_string()))?;
        file.write_all(b"\n")
            .await
            .map_err(|e| AuditError::LoggingError(e.to_string()))?;

        Ok(())
    }
}
