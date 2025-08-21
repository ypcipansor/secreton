use super::{Secret, SecretMetadata, SecretsEngine, SecretsError};
use crate::services::policy::PolicySet;
use crate::audit::{AuditLogger, AuditLog, AuditStatus};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// In-memory secrets engine: secrets only live in RAM, never written to disk
pub struct MemorySecretsEngine {
    secrets: Arc<RwLock<HashMap<String, Secret>>>,
    audit_logger: Option<AuditLogger>,
    policy_set: Option<PolicySet>,
}

impl MemorySecretsEngine {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
            audit_logger: None,
            policy_set: None,
        }
    }

    pub fn with_audit(audit_logger: AuditLogger) -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
            audit_logger: Some(audit_logger),
            policy_set: None,
        }
    }

    pub fn with_policy(policy_set: PolicySet) -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
            audit_logger: None,
            policy_set: Some(policy_set),
        }
    }

    pub fn with_audit_and_policy(audit_logger: AuditLogger, policy_set: PolicySet) -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
            audit_logger: Some(audit_logger),
            policy_set: Some(policy_set),
        }
    }

    async fn log_audit(&self, action: &str, path: &str, status: AuditStatus) {
        if let Some(logger) = &self.audit_logger {
            let entry = AuditLog {
                id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                action: action.to_string(),
                actor: None,
                resource_type: "secret".to_string(),
                resource_id: path.to_string(),
                status,
                ip: None,
                user_agent: None,
                metadata: HashMap::new(),
            };
            let _ = logger.log(entry).await;
        }
    }

    fn check_policy(&self, user: &str, path: &str, action: &str, context: Option<&serde_json::Value>) -> bool {
        if let Some(policy) = &self.policy_set {
            policy.evaluate(user, path, action, context)
        } else {
            true // default allow if no policy
        }
    }
}

#[async_trait]
impl SecretsEngine for MemorySecretsEngine {
    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        custom_metadata: Option<HashMap<String, String>>,
        user: &str,
        context: Option<&serde_json::Value>,
    ) -> Result<Secret, SecretsError> {
        if !self.check_policy(user, path, "create", context) {
            self.log_audit("create", path, AuditStatus::Denied).await;
            return Err(SecretsError::PermissionDenied);
        }
        let now = Utc::now();
        let ttl = custom_metadata.as_ref()
            .and_then(|m| m.get("ttl").and_then(|s| s.parse::<i64>().ok()));
        let expired_at = ttl.map(|t| now + chrono::Duration::seconds(t));
        let secret = Secret {
            id: Uuid::new_v4(),
            path: path.to_string(),
            data,
            metadata: SecretMetadata {
                created_at: now,
                updated_at: now,
                version: 1,
                ttl,
                expired_at,
                custom_metadata,
            },
        };
        self.secrets.write().unwrap().insert(path.to_string(), secret.clone());
        self.log_audit("create", path, AuditStatus::Success).await;
        Ok(secret)
    }

    async fn read_secret(&self, path: &str, user: &str, context: Option<&serde_json::Value>) -> Result<Secret, SecretsError> {
        if !self.check_policy(user, path, "read", context) {
            self.log_audit("read", path, AuditStatus::Denied).await;
            return Err(SecretsError::PermissionDenied);
        }
        let mut secrets = self.secrets.write().unwrap();
        if let Some(secret) = secrets.get(path) {
            if let Some(exp) = secret.metadata.expired_at {
                if Utc::now() > exp {
                    // Secret expired, auto-destroy
                    secrets.remove(path);
                    self.log_audit("read", path, AuditStatus::Denied).await;
                    return Err(SecretsError::NotFound);
                }
            }
            self.log_audit("read", path, AuditStatus::Success).await;
            return Ok(secret.clone());
        }
        self.log_audit("read", path, AuditStatus::Denied).await;
        Err(SecretsError::NotFound)
    }

    async fn update_secret(
        &self,
        path: &str,
        data: Value,
        custom_metadata: Option<HashMap<String, String>>,
        user: &str,
        context: Option<&serde_json::Value>,
    ) -> Result<Secret, SecretsError> {
        if !self.check_policy(user, path, "update", context) {
            self.log_audit("update", path, AuditStatus::Denied).await;
            return Err(SecretsError::PermissionDenied);
        }
        let mut secrets = self.secrets.write().unwrap();
        let secret = secrets.get_mut(path).ok_or(SecretsError::NotFound)?;
        secret.data = data;
        secret.metadata.updated_at = Utc::now();
        secret.metadata.version += 1;
        if let Some(meta) = &custom_metadata {
            if let Some(ttl_str) = meta.get("ttl") {
                if let Ok(ttl) = ttl_str.parse::<i64>() {
                    secret.metadata.ttl = Some(ttl);
                    secret.metadata.expired_at = Some(Utc::now() + chrono::Duration::seconds(ttl));
                }
            }
        }
        secret.metadata.custom_metadata = custom_metadata;
        self.log_audit("update", path, AuditStatus::Success).await;
        Ok(secret.clone())
    }

    async fn delete_secret(&self, path: &str, user: &str, context: Option<&serde_json::Value>) -> Result<(), SecretsError> {
        if !self.check_policy(user, path, "delete", context) {
            self.log_audit("delete", path, AuditStatus::Denied).await;
            return Err(SecretsError::PermissionDenied);
        }
        self.secrets.write().unwrap().remove(path);
        self.log_audit("delete", path, AuditStatus::Success).await;
        Ok(())
    }

    async fn list_secrets(&self, prefix: &str) -> Result<Vec<String>, SecretsError> {
        let secrets = self.secrets.read().unwrap();
        Ok(secrets
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}
