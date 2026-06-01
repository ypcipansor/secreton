// Secret Lifecycle Management - Expiration policies and automatic archival
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing;

use reqwest;

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Lifecycle error: {0}")]
    LifecycleError(String),
    #[error("Hook error: {0}")]
    HookError(String),
}

pub type Result<T> = std::result::Result<T, LifecycleError>;

pub use secreton_common::dto::lifecycle::{LifecycleStatistics, SecretLifecycle, SecretStatus};

/// Hook type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HookType {
    PreExpire,
    PostExpire,
    PreArchive,
    PostArchive,
}

/// Lifecycle configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleConfig {
    pub enabled: bool,
    pub default_ttl_days: u32,
    pub grace_period_days: u32,
    pub auto_archive_enabled: bool,
    pub cleanup_enabled: bool,
}

/// Expiration policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpirationPolicy {
    pub policy_id: String,
    pub _name: String,
    pub secret_pattern: String, // Regex pattern
    pub ttl_days: u32,
    pub warning_threshold_days: u32,
    pub auto_extend_enabled: bool,
    pub notify_on_expiration: bool,
}

/// Lifecycle hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleHook {
    pub hook_id: String,
    pub hook_type: HookType,
    pub action_url: String, // Webhook URL
    pub enabled: bool,
}

/// Archive record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveRecord {
    pub archive_id: String,
    pub secret_path: String,
    pub archived_at: DateTime<Utc>,
    pub original_data_hash: String,
    pub storage_location: String,
}

/// Secret Lifecycle Management
pub struct SecretLifecycleManagement {
    _config: Arc<RwLock<LifecycleConfig>>,
    lifecycles: Arc<RwLock<HashMap<String, SecretLifecycle>>>,
    policies: Arc<RwLock<HashMap<String, ExpirationPolicy>>>,
    hooks: Arc<RwLock<HashMap<String, LifecycleHook>>>,
    archives: Arc<RwLock<HashMap<String, ArchiveRecord>>>,
    client: reqwest::Client,
}

impl SecretLifecycleManagement {
    pub fn new(_config: LifecycleConfig) -> Self {
        Self {
            _config: Arc::new(RwLock::new(_config)),
            lifecycles: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
            hooks: Arc::new(RwLock::new(HashMap::new())),
            archives: Arc::new(RwLock::new(HashMap::new())),
            client: reqwest::Client::new(),
        }
    }

    /// Set expiration for a _secret
    pub async fn set_expiration(
        &self,
        secret_path: String,
        ttl_days: u32,
    ) -> Result<SecretLifecycle> {
        let _config = self._config.read().await;
        let grace_period_days = _config.grace_period_days;
        drop(_config);

        let created_at = Utc::now();
        let expires_at = created_at + Duration::days(ttl_days as i64);

        let lifecycle = SecretLifecycle {
            secret_path: secret_path.clone(),
            created_at,
            expires_at,
            archived_at: None,
            status: SecretStatus::Active,
            ttl_days,
            grace_period_days,
        };

        let mut lifecycles = self.lifecycles.write().await;
        lifecycles.insert(secret_path, lifecycle.clone());

        Ok(lifecycle)
    }

    /// Check expiring secrets
    pub async fn check_expiring_secrets(&self, warning_days: u32) -> Vec<SecretLifecycle> {
        let lifecycles = self.lifecycles.read().await;
        let threshold = Utc::now() + Duration::days(warning_days as i64);

        lifecycles
            .values()
            .filter(|lc| {
                lc.status == SecretStatus::Active
                    && lc.expires_at <= threshold
                    && lc.expires_at > Utc::now()
            })
            .cloned()
            .collect()
    }

    /// Expire secret
    pub async fn expire_secret(&self, secret_path: &str) -> Result<()> {
        let mut lifecycles = self.lifecycles.write().await;
        let lifecycle = lifecycles
            .get_mut(secret_path)
            .ok_or_else(|| LifecycleError::LifecycleError("Lifecycle not found".to_string()))?;

        lifecycle.status = SecretStatus::Expired;
        drop(lifecycles);

        // Trigger PostExpire hook
        self.trigger_lifecycle_hook(HookType::PostExpire, secret_path)
            .await?;

        Ok(())
    }

    /// Archive secret
    pub async fn archive_secret(&self, secret_path: &str) -> Result<ArchiveRecord> {
        // Trigger PreArchive hook
        self.trigger_lifecycle_hook(HookType::PreArchive, secret_path)
            .await?;

        let mut lifecycles = self.lifecycles.write().await;
        let lifecycle = lifecycles
            .get_mut(secret_path)
            .ok_or_else(|| LifecycleError::LifecycleError("Lifecycle not found".to_string()))?;

        lifecycle.status = SecretStatus::Archived;
        lifecycle.archived_at = Some(Utc::now());
        drop(lifecycles);

        // Create archive record
        let archive_record = ArchiveRecord {
            archive_id: uuid::Uuid::new_v4().to_string(),
            secret_path: secret_path.to_string(),
            archived_at: Utc::now(),
            original_data_hash: self.mock_calculate_hash(secret_path),
            storage_location: format!("/archives/{}", secret_path),
        };

        let mut archives = self.archives.write().await;
        archives.insert(secret_path.to_string(), archive_record.clone());

        // Trigger PostArchive hook
        self.trigger_lifecycle_hook(HookType::PostArchive, secret_path)
            .await?;

        Ok(archive_record)
    }

    /// Remove the lifecycle tracking entry for a secret.
    ///
    /// Called by callers (e.g. `SecretService::delete_secret_internal`,
    /// or `put_secret_internal` when an update clears `expires_at`) to keep
    /// the in-memory tracking state in sync with the authoritative storage
    /// record.  Returning `Ok(false)` (rather than an error) when no entry
    /// exists lets callers invoke this unconditionally without needing a
    /// pre-check, since the lifecycle manager's state is ephemeral and may
    /// legitimately not contain a path that storage knows about (e.g. after
    /// a server restart).
    pub async fn remove_expiration(&self, secret_path: &str) -> Result<bool> {
        let mut lifecycles = self.lifecycles.write().await;
        Ok(lifecycles.remove(secret_path).is_some())
    }

    /// Extend TTL
    pub async fn extend_ttl(
        &self,
        secret_path: &str,
        additional_days: u32,
    ) -> Result<SecretLifecycle> {
        let mut lifecycles = self.lifecycles.write().await;
        let lifecycle = lifecycles
            .get_mut(secret_path)
            .ok_or_else(|| LifecycleError::LifecycleError("Lifecycle not found".to_string()))?;

        lifecycle.expires_at += Duration::days(additional_days as i64);
        lifecycle.status = SecretStatus::Active;
        lifecycle.ttl_days += additional_days;

        Ok(lifecycle.clone())
    }

    /// Trigger lifecycle hook
    pub async fn trigger_lifecycle_hook(
        &self,
        hook_type: HookType,
        secret_path: &str,
    ) -> Result<()> {
        let hooks = self.hooks.read().await;

        let relevant_hooks: Vec<_> = hooks
            .values()
            .filter(|h| h.hook_type == hook_type && h.enabled)
            .collect();

        for hook in relevant_hooks {
            self.call_webhook(&hook.action_url, secret_path).await?;
        }

        Ok(())
    }

    /// Register policy
    pub async fn register_policy(&self, policy: ExpirationPolicy) -> Result<()> {
        let mut policies = self.policies.write().await;
        policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    /// Register hook
    pub async fn register_hook(&self, hook: LifecycleHook) -> Result<()> {
        let mut hooks = self.hooks.write().await;
        hooks.insert(hook.hook_id.clone(), hook);
        Ok(())
    }

    /// List by status
    pub async fn list_by_status(&self, status: SecretStatus) -> Vec<SecretLifecycle> {
        let lifecycles = self.lifecycles.read().await;
        lifecycles
            .values()
            .filter(|lc| lc.status == status)
            .cloned()
            .collect()
    }

    /// Cleanup expired secrets
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let _config = self._config.read().await;
        if !_config.cleanup_enabled {
            return Ok(0);
        }

        let grace_period_days = _config.grace_period_days;
        drop(_config);

        let threshold = Utc::now() - Duration::days(grace_period_days as i64);

        let lifecycles = self.lifecycles.read().await;
        let to_cleanup: Vec<_> = lifecycles
            .values()
            .filter(|lc| lc.status == SecretStatus::Expired && lc.expires_at < threshold)
            .map(|lc| lc.secret_path.clone())
            .collect();
        drop(lifecycles);

        let mut lifecycles = self.lifecycles.write().await;
        for _path in &to_cleanup {
            lifecycles.remove(_path);
        }

        Ok(to_cleanup.len())
    }

    /// Get lifecycle
    pub async fn get_lifecycle(&self, secret_path: &str) -> Option<SecretLifecycle> {
        let lifecycles = self.lifecycles.read().await;
        lifecycles.get(secret_path).cloned()
    }

    /// List policies
    pub async fn list_policies(&self) -> Vec<ExpirationPolicy> {
        let policies = self.policies.read().await;
        policies.values().cloned().collect()
    }

    /// List archives
    pub async fn list_archives(&self) -> Vec<ArchiveRecord> {
        let archives = self.archives.read().await;
        archives.values().cloned().collect()
    }

    // Helper methods

    fn mock_calculate_hash(&self, _secret_path: &str) -> String {
        format!("sha256:{}", uuid::Uuid::new_v4())
    }

    async fn call_webhook(&self, url: &str, secret_path: &str) -> Result<()> {
        let payload = serde_json::json!({
            "secret_path": secret_path,
            "timestamp": Utc::now(),
            "event": "lifecycle_event"
        });

        match self.client.post(url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(
                    "Successfully triggered webhook for {}: {}",
                    secret_path,
                    url
                );
                Ok(())
            }
            Ok(resp) => {
                let status = resp.status();
                tracing::error!(
                    "Webhook failed for {} with status {}: {}",
                    secret_path,
                    status,
                    url
                );
                Err(LifecycleError::HookError(format!(
                    "Webhook returned status {}",
                    status
                )))
            }
            Err(e) => {
                tracing::error!(
                    "Failed to send webhook for {}: {} - {}",
                    secret_path,
                    url,
                    e
                );
                Err(LifecycleError::HookError(e.to_string()))
            }
        }
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> LifecycleStatistics {
        let lifecycles = self.lifecycles.read().await;
        let archives = self.archives.read().await;

        let total_secrets = lifecycles.len();
        let active_secrets = lifecycles
            .values()
            .filter(|lc| lc.status == SecretStatus::Active)
            .count();
        let expiring_secrets = lifecycles
            .values()
            .filter(|lc| lc.status == SecretStatus::Expiring)
            .count();
        let expired_secrets = lifecycles
            .values()
            .filter(|lc| lc.status == SecretStatus::Expired)
            .count();
        let archived_secrets = archives.len();

        LifecycleStatistics {
            total_secrets,
            active_secrets,
            expiring_secrets,
            expired_secrets,
            archived_secrets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> LifecycleConfig {
        LifecycleConfig {
            enabled: true,
            default_ttl_days: 90,
            grace_period_days: 7,
            auto_archive_enabled: true,
            cleanup_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_set_expiration() {
        let lifecycle_mgmt = SecretLifecycleManagement::new(create_test_config());

        let lifecycle = lifecycle_mgmt
            .set_expiration("_secret/db/_password".to_string(), 90)
            .await
            .unwrap();

        assert_eq!(lifecycle.ttl_days, 90);
        assert_eq!(lifecycle.status, SecretStatus::Active);
    }

    #[tokio::test]
    async fn test_check_expiring_secrets() {
        let lifecycle_mgmt = SecretLifecycleManagement::new(create_test_config());

        lifecycle_mgmt
            .set_expiration("_secret/expiring".to_string(), 5)
            .await
            .unwrap();

        lifecycle_mgmt
            .set_expiration("_secret/active".to_string(), 90)
            .await
            .unwrap();

        let expiring = lifecycle_mgmt.check_expiring_secrets(7).await;
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].secret_path, "_secret/expiring");
    }

    #[tokio::test]
    async fn test_expire_secret() {
        let lifecycle_mgmt = SecretLifecycleManagement::new(create_test_config());

        lifecycle_mgmt
            .set_expiration("_secret/test".to_string(), 90)
            .await
            .unwrap();

        // Register PostExpire hook
        let hook = LifecycleHook {
            hook_id: "hook1".to_string(),
            hook_type: HookType::PostExpire,
            action_url: "http://webhook.example.com".to_string(),
            enabled: true,
        };
        lifecycle_mgmt.register_hook(hook).await.unwrap();

        lifecycle_mgmt.expire_secret("_secret/test").await.unwrap();

        let lifecycle = lifecycle_mgmt.get_lifecycle("_secret/test").await.unwrap();
        assert_eq!(lifecycle.status, SecretStatus::Expired);
    }

    #[tokio::test]
    async fn test_archive_secret() {
        let lifecycle_mgmt = SecretLifecycleManagement::new(create_test_config());

        lifecycle_mgmt
            .set_expiration("_secret/archive".to_string(), 90)
            .await
            .unwrap();

        let archive = lifecycle_mgmt
            .archive_secret("_secret/archive")
            .await
            .unwrap();

        assert_eq!(archive.secret_path, "_secret/archive");
        assert!(!archive.original_data_hash.is_empty());

        let lifecycle = lifecycle_mgmt
            .get_lifecycle("_secret/archive")
            .await
            .unwrap();
        assert_eq!(lifecycle.status, SecretStatus::Archived);
    }

    #[tokio::test]
    async fn test_extend_ttl() {
        let lifecycle_mgmt = SecretLifecycleManagement::new(create_test_config());

        lifecycle_mgmt
            .set_expiration("_secret/extend".to_string(), 30)
            .await
            .unwrap();

        let extended = lifecycle_mgmt
            .extend_ttl("_secret/extend", 30)
            .await
            .unwrap();

        assert_eq!(extended.ttl_days, 60);
        assert_eq!(extended.status, SecretStatus::Active);
    }
}
