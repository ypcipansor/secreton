//! Lifecycle service for managing secret expiration and archival.

use anyhow::Result;
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, interval_at};
use tracing::{error, info, warn};

use crate::services::audit::{AuditLogger, SecurityEventType};
use crate::services::crypto::CryptoService;
use secreton_integrations::integrations::secret_lifecycle_management::{
    HookType, LifecycleConfig, LifecycleHook, SecretLifecycleManagement,
};
use secreton_storage::{EncryptionMetadata, QueryParams, SecretEntry, SecurityLevel, StorageBackend};

/// Reserved path prefixes that must NOT be swept by the lifecycle worker.
const RESERVED_PATH_PREFIXES: &[&str] = &[
    "sys/",
    "keys/",
    "key_data/",
    "sessions/",
    "users/",
    "db/",
    "totp/",
    "pki/",
    "auth/",
    "mfa/",
    "policies/",
    "backups/",
    "config/",
];

/// Actor string recorded in the audit trail for automated lifecycle deletions.
const LIFECYCLE_AUDIT_ACTOR: &str = "system:lifecycle";

pub struct LifecycleService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    audit: Arc<AuditLogger>,
    manager: Arc<SecretLifecycleManagement>,
    shutdown: Arc<Notify>,
    enabled: bool,
    cleanup_enabled: bool,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl LifecycleService {
    pub fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        audit: Arc<AuditLogger>,
        config: LifecycleConfig,
    ) -> Self {
        let enabled = config.enabled;
        let cleanup_enabled = config.cleanup_enabled;
        Self {
            storage,
            crypto,
            audit,
            manager: Arc::new(SecretLifecycleManagement::new(config)),
            shutdown: Arc::new(Notify::new()),
            enabled,
            cleanup_enabled,
            worker: Mutex::new(None),
        }
    }

    fn is_reserved_path(path: &str) -> bool {
        RESERVED_PATH_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }

    pub async fn spawn_worker(self: &Arc<Self>) {
        if !self.enabled {
            info!("Secret Lifecycle service is disabled; worker will not be spawned");
            return;
        }

        if let Err(e) = self.hydrate_hooks().await {
            warn!("Failed to hydrate hooks: {}", e);
        }

        let mut guard = self.worker.lock().await;
        if guard.is_some() {
            return;
        }
        let weak = Arc::downgrade(self);
        let handle = tokio::spawn(start_worker(weak));
        *guard = Some(handle);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    pub async fn shutdown_and_wait(&self) {
        self.shutdown.notify_one();
        let handle = {
            let mut guard = self.worker.lock().await;
            guard.take()
        };
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }

    pub async fn process_lifecycle_events(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.cleanup_enabled {
            let _ = self.sweep_expired_secrets().await;
        }

        if let Err(e) = self.manager.cleanup_expired().await {
            warn!("Failed to cleanup manager: {}", e);
        }

        Ok(())
    }

    pub fn manager(&self) -> Arc<SecretLifecycleManagement> {
        self.manager.clone()
    }

    pub async fn list_hooks(&self) -> Result<Vec<LifecycleHook>> {
        let query = QueryParams {
            path_prefix: Some("sys/lifecycle/hooks/".to_string()),
            ..Default::default()
        };

        let entries = self.storage.list(&query).await?;
        let mut hooks = Vec::new();

        for entry in entries {
            if let Ok(decrypted) = self.crypto.decrypt(&entry.encrypted_data).await {
                if let Ok(hook) = serde_json::from_slice::<LifecycleHook>(&decrypted) {
                    hooks.push(hook);
                }
            }
        }
        Ok(hooks)
    }

    pub async fn get_hook(&self, hook_id: &str) -> Result<Option<LifecycleHook>> {
        let path = format!("sys/lifecycle/hooks/{}", hook_id);
        if let Some(entry) = self.storage.get_by_path(&path).await? {
            let decrypted = self.crypto.decrypt(&entry.encrypted_data).await?;
            let hook = serde_json::from_slice::<LifecycleHook>(&decrypted)?;
            Ok(Some(hook))
        } else {
            Ok(None)
        }
    }

    pub async fn create_hook(&self, hook: LifecycleHook) -> Result<()> {
        let path = format!("sys/lifecycle/hooks/{}", hook.hook_id);
        let data = serde_json::to_vec(&hook)?;
        let encrypted_data = self.crypto.encrypt_data(&data).await?;

        let mut entry = SecretEntry::new(path, encrypted_data, EncryptionMetadata::default(), SecurityLevel::Secret, uuid::Uuid::nil());
        entry.id = uuid::Uuid::new_v4();
        self.storage.store(&entry).await?;
        self.manager.register_hook(hook).await.map_err(|e| anyhow::anyhow!(e))?;
        Ok(())
    }

    pub async fn update_hook(&self, hook: LifecycleHook) -> Result<()> {
        let path = format!("sys/lifecycle/hooks/{}", hook.hook_id);
        if let Some(existing) = self.storage.get_by_path(&path).await? {
            let data = serde_json::to_vec(&hook)?;
            let encrypted_data = self.crypto.encrypt_data(&data).await?;
            let mut entry = SecretEntry::new(path, encrypted_data, EncryptionMetadata::default(), SecurityLevel::Secret, uuid::Uuid::nil());
            entry.id = existing.id;
            entry.version = existing.version + 1;
            self.storage.update(&entry).await?;
            self.manager.register_hook(hook).await.map_err(|e| anyhow::anyhow!(e))?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Hook not found"))
        }
    }

    pub async fn delete_hook(&self, hook_id: &str) -> Result<()> {
        let path = format!("sys/lifecycle/hooks/{}", hook_id);
        self.storage.delete_by_path(&path).await?;
        Ok(())
    }

    pub async fn hydrate_hooks(&self) -> Result<()> {
        let hooks = self.list_hooks().await?;
        for hook in hooks {
            let _ = self.manager.register_hook(hook).await;
        }
        Ok(())
    }

    fn shutdown_handle(&self) -> Arc<Notify> {
        self.shutdown.clone()
    }

    async fn sweep_expired_secrets(&self) -> Result<u64> {
        const SWEEP_MAX_ENTRIES: u32 = 10_000;
        let params = QueryParams {
            include_expired: true,
            limit: Some(SWEEP_MAX_ENTRIES),
            sort_by: Some("expires_at".to_string()),
            sort_order: Some("asc".to_string()),
            excluded_path_prefixes: RESERVED_PATH_PREFIXES.iter().map(|p| (*p).to_string()).collect(),
            ..Default::default()
        };

        let entries = self.storage.list(&params).await?;
        let mut deleted: u64 = 0;

        for entry in entries {
            if !entry.is_expired() || Self::is_reserved_path(&entry.path) {
                continue;
            }

            if let Some(fresh) = self.storage.get_by_id(entry.id).await? {
                if fresh.is_expired() {
                    let _ = self.manager.trigger_lifecycle_hook(HookType::PostExpire, &fresh.path).await;
                    if self.storage.delete_by_id(fresh.id).await? {
                        deleted += 1;
                        self.audit.log_event(SecurityEventType::SecretDeletion {
                            secret_path: fresh.path.clone(),
                            user: LIFECYCLE_AUDIT_ACTOR.to_string(),
                        }).await;
                        self.cleanup_history_for(&fresh.path).await;
                        let _ = self.manager.remove_expiration(&fresh.path).await;
                    }
                }
            }
        }
        Ok(deleted)
    }

    async fn cleanup_history_for(&self, path: &str) {
        let history_prefix = format!("sys/history/{}::v", path);
        let query = QueryParams {
            path_prefix: Some(history_prefix),
            limit: Some(10_000),
            include_expired: true,
            ..Default::default()
        };

        if let Ok(entries) = self.storage.list(&query).await {
            for entry in entries {
                let _ = self.storage.delete_by_id(entry.id).await;
            }
        }
    }
}

async fn start_worker(weak: Weak<LifecycleService>) {
    let shutdown = match weak.upgrade() {
        Some(svc) => svc.shutdown_handle(),
        None => return,
    };

    let period = Duration::from_secs(3600);
    let mut ticker = interval_at(Instant::now() + period, period);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.notified() => break,
            _ = ticker.tick() => {
                if let Some(svc) = weak.upgrade() {
                    let _ = svc.process_lifecycle_events().await;
                } else {
                    break;
                }
            }
        }
    }
}

impl Drop for LifecycleService {
    fn drop(&mut self) {
        self.shutdown.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secreton_storage::MockStorageBackend;

    async fn make_service(enabled: bool, cleanup_enabled: bool) -> Arc<LifecycleService> {
        let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(crate::services::crypto::CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(crate::services::audit::AuditLogger::new(storage.clone(), 30, 100, false).await.unwrap());
        let cfg = LifecycleConfig { enabled, default_ttl_days: 90, grace_period_days: 7, auto_archive_enabled: false, cleanup_enabled };
        Arc::new(LifecycleService::new(storage, crypto, audit, cfg))
    }

    #[tokio::test]
    async fn disabled_service_skips_processing() {
        let svc = make_service(false, true).await;
        svc.process_lifecycle_events().await.unwrap();
    }
}
