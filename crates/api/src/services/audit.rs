use crate::services::audit_storage::StorageAuditDevice;
use anyhow::Result;
use secreton_security::policies::audit::{
    AuditEvent, AuditEventType as CoreAuditEventType, AuditService, AuditStatus,
};
use secreton_storage::StorageBackend;
use std::sync::Arc;

/// Audit logger service adapter
pub struct AuditLogger {
    service: Arc<AuditService>,
}

impl AuditLogger {
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        retention_days: u32,
    ) -> Result<Self> {
        let service = Arc::new(AuditService::new(1000));
        let device = StorageAuditDevice::new(storage, retention_days);
        service.add_device(Box::new(device)).await;
        Ok(Self { service })
    }

    pub async fn flush(&self) -> Result<()> {
        self.service
            .flush()
            .await
            .map_err(|e| anyhow::anyhow!("Audit flush failed: {}", e))
    }

    pub async fn log_event(&self, event: SecurityEventType) {
        let (core_type, status, user, resource, op, metadata) = match event {
            SecurityEventType::SecretAccess {
                secret_path,
                user,
                action,
            } => (
                CoreAuditEventType::SecretRead,
                AuditStatus::Success,
                user,
                secret_path,
                action,
                None,
            ),
            SecurityEventType::SecretCreation { secret_path, user } => (
                CoreAuditEventType::SecretWrite,
                AuditStatus::Success,
                user,
                secret_path,
                "create".to_string(),
                None,
            ),
            SecurityEventType::SecretVersionChange {
                secret_path,
                old_version,
                new_version,
                user,
            } => (
                CoreAuditEventType::SecretWrite,
                AuditStatus::Success,
                user,
                secret_path,
                "update_version".to_string(),
                Some(
                    vec![
                        ("old_version".to_string(), old_version.to_string()),
                        ("new_version".to_string(), new_version.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::SecretDeletion { secret_path, user } => (
                CoreAuditEventType::SecretDelete,
                AuditStatus::Success,
                user,
                secret_path,
                "delete".to_string(),
                None,
            ),
            SecurityEventType::KeyGeneration {
                key_type,
                key_id,
                algorithm,
                user,
            } => (
                CoreAuditEventType::Custom("key.generate".to_string()),
                AuditStatus::Success,
                user,
                key_id,
                "generate".to_string(),
                Some(
                    vec![
                        ("key_type".to_string(), key_type.to_string()),
                        ("algorithm".to_string(), algorithm.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::KeyRotation {
                old_key_id,
                new_key_id,
                algorithm,
                user,
            } => (
                CoreAuditEventType::Custom("key.rotate".to_string()),
                AuditStatus::Success,
                user,
                new_key_id,
                "rotate".to_string(),
                Some(
                    vec![
                        ("old_key_id".to_string(), old_key_id),
                        ("algorithm".to_string(), algorithm.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::EncryptionOperation {
                key_id,
                user,
                data_size,
            } => (
                CoreAuditEventType::Custom("crypto.encrypt".to_string()),
                AuditStatus::Success,
                user,
                key_id,
                "encrypt".to_string(),
                Some(
                    vec![("data_size".to_string(), data_size.to_string())]
                        .into_iter()
                        .collect(),
                ),
            ),
            SecurityEventType::DecryptionOperation {
                key_id,
                user,
                data_size,
            } => (
                CoreAuditEventType::Custom("crypto.decrypt".to_string()),
                AuditStatus::Success,
                user,
                key_id,
                "decrypt".to_string(),
                Some(
                    vec![("data_size".to_string(), data_size.to_string())]
                        .into_iter()
                        .collect(),
                ),
            ),
            SecurityEventType::AuthenticationSuccess { user, method } => (
                CoreAuditEventType::AuthLogin,
                AuditStatus::Success,
                user,
                "auth".to_string(),
                "login".to_string(),
                Some(vec![("method".to_string(), method)].into_iter().collect()),
            ),
            SecurityEventType::AuthenticationFailure {
                user,
                method,
                reason,
            } => (
                CoreAuditEventType::AuthLogin,
                AuditStatus::Failure,
                user,
                "auth".to_string(),
                "login".to_string(),
                Some(
                    vec![
                        ("method".to_string(), method),
                        ("reason".to_string(), reason),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::SessionTerminated {
                user,
                session_id,
                reason,
            } => (
                CoreAuditEventType::AuthLogout,
                AuditStatus::Success,
                user,
                "session".to_string(),
                "terminate".to_string(),
                Some(
                    vec![
                        ("session_id".to_string(), session_id),
                        ("reason".to_string(), reason),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::MfaSetup { user, method } => (
                CoreAuditEventType::Custom("mfa.setup".to_string()),
                AuditStatus::Success,
                user,
                "mfa".to_string(),
                "setup".to_string(),
                Some(vec![("method".to_string(), method)].into_iter().collect()),
            ),
            SecurityEventType::MFASuccess { user, method } => (
                CoreAuditEventType::Custom("mfa.verify".to_string()),
                AuditStatus::Success,
                user,
                "mfa".to_string(),
                "verify".to_string(),
                Some(vec![("method".to_string(), method)].into_iter().collect()),
            ),
            SecurityEventType::MFARemoval { user, method } => (
                CoreAuditEventType::Custom("mfa.remove".to_string()),
                AuditStatus::Success,
                user,
                "mfa".to_string(),
                "remove".to_string(),
                Some(vec![("method".to_string(), method)].into_iter().collect()),
            ),
            SecurityEventType::LoginSuccess {
                user,
                method,
                ip_address,
            } => (
                CoreAuditEventType::AuthLogin,
                AuditStatus::Success,
                user,
                "auth".to_string(),
                "login".to_string(),
                Some(
                    vec![
                        ("method".to_string(), method),
                        ("ip_address".to_string(), ip_address.unwrap_or_default()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::Logout {
                user,
                session_id,
                ip_address,
                user_agent,
            } => (
                CoreAuditEventType::AuthLogout,
                AuditStatus::Success,
                user,
                "session".to_string(),
                "logout".to_string(),
                Some(
                    vec![
                        ("session_id".to_string(), session_id),
                        ("ip_address".to_string(), ip_address.unwrap_or_default()),
                        ("user_agent".to_string(), user_agent.unwrap_or_default()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::SigningOperation {
                key_id,
                user,
                data_size,
            } => (
                CoreAuditEventType::Custom("crypto.sign".to_string()),
                AuditStatus::Success,
                user,
                key_id,
                "sign".to_string(),
                Some(
                    vec![("data_size".to_string(), data_size.to_string())]
                        .into_iter()
                        .collect(),
                ),
            ),
            SecurityEventType::VerificationOperation {
                key_id,
                user,
                data_size,
                valid,
            } => (
                CoreAuditEventType::Custom("crypto.verify".to_string()),
                if valid {
                    AuditStatus::Success
                } else {
                    AuditStatus::Failure
                },
                user,
                key_id,
                "verify".to_string(),
                Some(
                    vec![
                        ("data_size".to_string(), data_size.to_string()),
                        ("valid".to_string(), valid.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::PolicyChange {
                policy_name,
                user,
                action,
            } => (
                CoreAuditEventType::Custom("policy.change".to_string()),
                AuditStatus::Success,
                user,
                policy_name,
                action,
                None,
            ),
            SecurityEventType::ConfigChange { user, changed_keys } => (
                CoreAuditEventType::Custom("config.change".to_string()),
                AuditStatus::Success,
                user,
                "config".to_string(),
                "change".to_string(),
                Some(
                    vec![("changed_keys".to_string(), changed_keys.join(","))]
                        .into_iter()
                        .collect(),
                ),
            ),
            SecurityEventType::SealOperation {
                operation,
                user,
                success,
            } => (
                CoreAuditEventType::Custom("seal.operation".to_string()),
                if success {
                    AuditStatus::Success
                } else {
                    AuditStatus::Failure
                },
                user,
                "seal".to_string(),
                operation,
                Some(
                    vec![("success".to_string(), success.to_string())]
                        .into_iter()
                        .collect(),
                ),
            ),
        };

        let mut audit_event = AuditEvent::new(core_type, status, user, resource, op);
        if let Some(meta) = metadata {
            audit_event.metadata = meta;
        }
        self.service.log(audit_event).await;
    }
}

pub enum SecurityEventType {
    SecretAccess {
        secret_path: String,
        user: String,
        action: String,
    },
    SecretCreation {
        secret_path: String,
        user: String,
    },
    SecretVersionChange {
        secret_path: String,
        old_version: u32,
        new_version: u32,
        user: String,
    },
    SecretDeletion {
        secret_path: String,
        user: String,
    },
    KeyGeneration {
        key_type: String,
        key_id: String,
        algorithm: String,
        user: String,
    },
    KeyRotation {
        old_key_id: String,
        new_key_id: String,
        algorithm: String,
        user: String,
    },
    EncryptionOperation {
        key_id: String,
        user: String,
        data_size: u64,
    },
    DecryptionOperation {
        key_id: String,
        user: String,
        data_size: u64,
    },
    SigningOperation {
        key_id: String,
        user: String,
        data_size: u64,
    },
    VerificationOperation {
        key_id: String,
        user: String,
        data_size: u64,
        valid: bool,
    },
    PolicyChange {
        policy_name: String,
        user: String,
        action: String,
    },
    ConfigChange {
        user: String,
        changed_keys: Vec<String>,
    },
    SealOperation {
        operation: String,
        user: String,
        success: bool,
    },
    AuthenticationSuccess {
        user: String,
        method: String,
    },
    AuthenticationFailure {
        user: String,
        method: String,
        reason: String,
    },
    SessionTerminated {
        user: String,
        session_id: String,
        reason: String,
    },
    MfaSetup {
        user: String,
        method: String,
    },
    MFASuccess {
        user: String,
        method: String,
    },
    MFARemoval {
        user: String,
        method: String,
    },
    LoginSuccess {
        user: String,
        method: String,
        ip_address: Option<String>,
    },
    Logout {
        user: String,
        session_id: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub enum ExportFormat {
    CSV,
    XML,
    JSON,
    CEF,
    LEEF,
    SIEM,
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilters {
    pub user: Option<String>,
    pub action: Option<String>,
    pub path: Option<String>,
    pub start_date: Option<chrono::DateTime<chrono::Utc>>,
    pub end_date: Option<chrono::DateTime<chrono::Utc>>,
}

impl AuditFilters {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn by_user(user: String) -> Self {
        Self {
            user: Some(user),
            ..Default::default()
        }
    }
    pub fn by_path(path: String) -> Self {
        Self {
            path: Some(path),
            ..Default::default()
        }
    }
}

impl AuditLogger {
    /// Get audit entries based on filters
    pub async fn get_entries(
        &self,
        _filters: AuditFilters,
    ) -> Result<Vec<secreton_storage::models::storage_models::AuditEntry>> {
        // Placeholder
        Ok(vec![])
    }

    /// Export audit data
    pub async fn export_data(
        &self,
        _format: ExportFormat,
        _filters: AuditFilters,
    ) -> Result<Vec<u8>> {
        // Placeholder
        Ok(vec![])
    }
}
