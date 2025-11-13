//! Audit service module
//! Provides audit logging functionality for the Secreton system

use async_trait::async_trait;
use secreton_errors::SecretonError;
use secreton_security::policies::audit::{AuditDevice, AuditEvent, AuditEventType, AuditStatus};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Audit service for logging system events
#[derive(Clone)]
pub struct AuditService {
    devices: Arc<RwLock<Vec<Box<dyn AuditDevice>>>>,
}

impl AuditService {
    /// Create a new audit service
    pub fn new() -> Self {
        Self {
            devices: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register an audit device
    pub async fn register_device(&self, device: Box<dyn AuditDevice>) -> Result<(), SecretonError> {
        let mut devices = self.devices.write().await;
        devices.push(device);
        Ok(())
    }

    /// Log an audit event
    pub async fn log_event(
        &self,
        event_type: AuditEventType,
        user: Option<&str>,
        path: Option<&str>,
        status: AuditStatus,
        metadata: std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<(), SecretonError> {
        let metadata_str: HashMap<String, String> = metadata
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect();

        let event = AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type,
            status,
            user: user.unwrap_or("unknown").to_string(),
            display_name: None,
            client_ip: None,
            resource: path.map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string()),
            operation: "unknown".to_string(), // TODO: add operation parameter
            method: None,
            request_id: None,
            token_accessor: None,
            policies: Vec::new(),
            error: None,
            metadata: metadata_str,
            duration_ms: None,
        };

        let devices = self.devices.read().await;
        for device in devices.iter() {
            if let Err(e) = device.log(&event).await {
                tracing::warn!("Failed to log audit event to device: {:?}", e);
                // Continue with other devices even if one fails
            }
        }

        Ok(())
    }

    /// Log authentication event
    pub async fn log_auth_event(
        &self,
        event_type: AuditEventType,
        user: &str,
        success: bool,
    ) -> Result<(), SecretonError> {
        let status = if success { AuditStatus::Success } else { AuditStatus::Failure };
        self.log_event(event_type, Some(user), None, status, std::collections::HashMap::new()).await
    }

    /// Log secret operation
    pub async fn log_secret_operation(
        &self,
        event_type: AuditEventType,
        user: &str,
        path: &str,
        success: bool,
    ) -> Result<(), SecretonError> {
        let status = if success { AuditStatus::Success } else { AuditStatus::Failure };
        self.log_event(event_type, Some(user), Some(path), status, std::collections::HashMap::new()).await
    }

    /// Get all registered devices
    pub async fn get_devices(&self) -> Vec<Box<dyn AuditDevice>> {
        let _devices = self.devices.read().await;
        // Note: This clones the devices, in practice you might want to return references
        // or provide a different interface
        Vec::new() // Placeholder - would need to implement Clone for AuditDevice
    }
}

impl Default for AuditService {
    fn default() -> Self {
        Self::new()
    }
}

/// External audit device trait
#[async_trait]
pub trait ExternalAuditDevice: Send + Sync {
    /// Send audit log to external device
    async fn send_audit_log(&self, log: &str) -> Result<(), Box<dyn std::error::Error>>;
}
