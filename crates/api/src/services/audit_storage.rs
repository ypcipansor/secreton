use std::sync::Arc;
use async_trait::async_trait;
use chrono::{Datelike, Utc};
use secreton_storage::{
    EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend,
};
use secreton_security::policies::audit::{AuditDevice, AuditEvent};
use uuid::Uuid;
use tracing::error;

/// Storage-backed audit device that persists audit events as SecretEntry records
pub struct StorageAuditDevice {
    storage: Arc<dyn StorageBackend + Send + Sync>,
}

impl StorageAuditDevice {
    pub fn new(storage: Arc<dyn StorageBackend + Send + Sync>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl AuditDevice for StorageAuditDevice {
    async fn log(
        &self,
        event: &AuditEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Serialize event to JSON
        let event_json = serde_json::to_string(event)?;

        // Construct storage path: sys/audit/YYYY/MM/DD/{timestamp}-{id}
        let path = format!(
            "sys/audit/{}/{:02}/{:02}/{}-{}",
            event.timestamp.format("%Y"),
            event.timestamp.format("%m"),
            event.timestamp.format("%d"),
            event.timestamp.timestamp(),
            event.id
        );

        // Create SecretEntry
        // Note: AdminService expects data in metadata["log_data"]
        let entry = SecretEntry::new(
            path,
            Vec::new(), // No encrypted payload, data is in metadata
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::nil(), // System owner
        )
        .add_metadata("log_data".to_string(), event_json)
        .add_metadata("event_type".to_string(), event.event_type.as_str().to_string())
        .add_metadata("user".to_string(), event.user.clone())
        .add_metadata("status".to_string(), event.status.as_str().to_string());

        // Store it
        if let Err(e) = self.storage.store(&entry).await {
            error!("Failed to persist audit log: {}", e);
            return Err(Box::new(e));
        }

        Ok(())
    }
}
