//! Audit log storage backends

use async_trait::async_trait;
use sqlx::{Pool, Sqlite};
use std::path::Path;
use super::*;

/// SQLite backend for audit logs
pub struct SqliteBackend {
    pool: Pool<Sqlite>,
}

impl SqliteBackend {
    /// Create a new SQLite backend
    pub async fn new(db_path: impl AsRef<Path>) -> Result<Self, sqlx::Error> {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(db_path.as_ref().to_str().unwrap())
            .await?;
            
        // Create the audit logs table if it doesn't exist
        sqlx::migrate!("./migrations/audit")
            .run(&pool)
            .await?;
            
        Ok(Self { pool })
    }
}

#[async_trait]
impl AuditBackend for SqliteBackend {
    async fn log(&self, entry: AuditLog) -> Result<(), AuditError> {
        let metadata = serde_json::to_string(&entry.metadata)
            .map_err(|e| AuditError::LoggingError(e.to_string()))?;
            
        sqlx::query!(
            r#"
            INSERT INTO audit_logs (
                id, timestamp, action, actor_id, resource_type, 
                resource_id, status, ip, user_agent, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            entry.id.to_string(),
            entry.timestamp,
            entry.action,
            entry.actor.map(|id| id.to_string()),
            entry.resource_type,
            entry.resource_id,
            match entry.status {
                AuditStatus::Success => "success",
                AuditStatus::Failure => "failure",
                AuditStatus::Denied => "denied",
            },
            entry.ip,
            entry.user_agent,
            metadata,
        )
        .execute(&self.pool)
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
        let line = serde_json::to_string(&entry)
            .map_err(|e| AuditError::LoggingError(e.to_string()))?;
            
        use tokio::io::AsyncWriteExt;
        file.write_all(line.as_bytes()).await
            .map_err(|e| AuditError::LoggingError(e.to_string()))?;
        file.write_all(b"\n").await
            .map_err(|e| AuditError::LoggingError(e.to_string()))?;
            
        Ok(())
    }
}
