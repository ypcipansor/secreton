use super::{Secret, SecretMetadata, SecretsEngine, SecretsError};
use crate::audit::{AuditLog, AuditLogger, AuditStatus};
use crate::services::policy::PolicySet;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// In-memory secrets engine: secrets only live in RAM, never written to disk
#[allow(dead_code)]
pub struct MemorySecretsEngine {
    secrets: Arc<std::sync::RwLock<HashMap<String, Secret>>>,
    audit_logger: Option<AuditLogger>,
    policy_set: Option<PolicySet>,
}

impl Default for MemorySecretsEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MemorySecretsEngine {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(std::sync::RwLock::new(HashMap::new())),
            audit_logger: None,
            policy_set: None,
        }
    }

    pub fn with_audit(audit_logger: AuditLogger) -> Self {
        Self {
            secrets: Arc::new(std::sync::RwLock::new(HashMap::new())),
            audit_logger: Some(audit_logger),
            policy_set: None,
        }
    }

    pub fn with_policy(policy_set: PolicySet) -> Self {
        Self {
            secrets: Arc::new(std::sync::RwLock::new(HashMap::new())),
            audit_logger: None,
            policy_set: Some(policy_set),
        }
    }

    pub fn with_audit_and_policy(audit_logger: AuditLogger, policy_set: PolicySet) -> Self {
        Self {
            secrets: Arc::new(std::sync::RwLock::new(HashMap::new())),
            audit_logger: Some(audit_logger),
            policy_set: Some(policy_set),
        }
    }

    #[allow(dead_code)]
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

            if let Err(e) = logger.log(entry).await {
                eprintln!("Failed to log audit event: {}", e);
            }
        }
    }

    #[allow(dead_code)]
    fn check_policy(
        &self,
        user: &str,
        path: &str,
        action: &str,
        context: Option<&serde_json::Value>,
    ) -> bool {
        if let Some(policy) = &self.policy_set {
            policy.evaluate(user, path, action, context)
        } else {
            true // default allow if no policy
        }
    }
}

#[async_trait]
impl SecretsEngine for MemorySecretsEngine {
    fn engine_type(&self) -> &'static str {
        "memory"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        let now = Utc::now();
        let custom_metadata = options
            .as_ref()
            .and_then(|o| o.get("custom_metadata"))
            .and_then(|m| serde_json::from_value(m.clone()).ok());

        let ttl = custom_metadata
            .as_ref()
            .and_then(|m: &HashMap<String, String>| {
                m.get("ttl").and_then(|s| s.parse::<i64>().ok())
            });
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
        self.secrets
            .write()
            .unwrap()
            .insert(path.to_string(), secret.clone());
        Ok(secret)
    }

    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError> {
        let mut secrets = self.secrets.write().unwrap();
        if let Some(secret) = secrets.get(path) {
            if let Some(exp) = secret.metadata.expired_at {
                if Utc::now() > exp {
                    // Secret expired, auto-destroy
                    secrets.remove(path);
                    return Err(SecretsError::NotFound(format!("Secret expired: {}", path)));
                }
            }
            return Ok(secret.clone());
        }
        Err(SecretsError::NotFound(format!(
            "Secret not found: {}",
            path
        )))
    }

    async fn update_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        let mut secrets = self.secrets.write().unwrap();
        let secret = secrets
            .get_mut(path)
            .ok_or_else(|| SecretsError::NotFound(format!("Secret '{}' not found", path)))?;
        secret.data = data;
        secret.metadata.updated_at = Utc::now();
        secret.metadata.version += 1;

        if let Some(opts) = &options {
            if let Some(meta) = opts.get("custom_metadata") {
                if let Ok(custom_meta) =
                    serde_json::from_value::<HashMap<String, String>>(meta.clone())
                {
                    if let Some(ttl_str) = custom_meta.get("ttl") {
                        if let Ok(ttl) = ttl_str.parse::<i64>() {
                            secret.metadata.ttl = Some(ttl);
                            secret.metadata.expired_at =
                                Some(Utc::now() + chrono::Duration::seconds(ttl));
                        }
                    }
                    secret.metadata.custom_metadata = Some(custom_meta);
                }
            }
        }

        Ok(secret.clone())
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        self.secrets.write().unwrap().remove(path);
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

    async fn collect_metrics(&self) -> Result<super::EngineMetrics, super::SecretsError> {
        let secrets = self.secrets.read().unwrap();
        let active_secrets = secrets.len() as u64;

        Ok(super::EngineMetrics {
            engine_type: self.engine_type().to_string(),
            secrets_created: 0,
            secrets_read: 0,
            secrets_updated: 0,
            secrets_deleted: 0,
            avg_response_time_ms: 0.0,
            error_count: 0,
            active_secrets,
            storage_size_bytes: 0, // Memory engine doesn't track storage size
        })
    }
}
