//! Lifecycle service for managing secret expiration and archival.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, interval_at};
use tracing::{error, info, warn};

use crate::services::audit::{AuditLogger, SecurityEventType};
use crate::services::secret::SecretService;
use secreton_integrations::integrations::secret_lifecycle_management::{
    LifecycleConfig, SecretLifecycleManagement,
};
use secreton_storage::{QueryParams, StorageBackend};

/// Reserved path prefixes that must NOT be swept by the lifecycle worker.
///
/// These namespaces are owned by other subsystems (version history, policies,
/// encryption key material, audit log, backups) and have their own retention
/// or cleanup policies. Blanket-deleting expired entries across them would
/// overlap with dedicated cleaners (e.g. `delete_expired_oauth_states`) and
/// could silently drop orphaned history or audit records that are still
/// referenced by the primary secret.
const RESERVED_PATH_PREFIXES: &[&str] = &[
    "sys/",
    "keys/",
    "key_data/",
];

/// Actor string recorded in the audit trail for automated lifecycle deletions.
/// Uses a `system:` prefix so that audit consumers can distinguish automated
/// sweeps from user-initiated `SecretService::delete_secret` calls (which
/// record the user's UUID).
const LIFECYCLE_AUDIT_ACTOR: &str = "system:lifecycle";

pub struct LifecycleService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    _secreton: Arc<SecretService>,
    audit: Arc<AuditLogger>,
    manager: Arc<SecretLifecycleManagement>,
    shutdown: Arc<Notify>,
    enabled: bool,
    /// When false, `process_lifecycle_events` skips the destructive
    /// storage sweep. Mirrors `LifecycleConfig.cleanup_enabled` so that the
    /// flag gates the primary cleanup path (not just the secondary in-memory
    /// manager cleanup).
    cleanup_enabled: bool,
    /// Handle for the background worker task, stored so that shutdown can
    /// await its completion and ensure any in-flight processing finishes.
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl LifecycleService {
    pub fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        secreton: Arc<SecretService>,
        audit: Arc<AuditLogger>,
        config: LifecycleConfig,
    ) -> Self {
        let enabled = config.enabled;
        let cleanup_enabled = config.cleanup_enabled;
        Self {
            storage,
            _secreton: secreton,
            audit,
            manager: Arc::new(SecretLifecycleManagement::new(config)),
            shutdown: Arc::new(Notify::new()),
            enabled,
            cleanup_enabled,
            worker: Mutex::new(None),
        }
    }

    /// Returns true if the given path belongs to a reserved namespace that
    /// must not be swept by the lifecycle worker. See `RESERVED_PATH_PREFIXES`.
    fn is_reserved_path(path: &str) -> bool {
        RESERVED_PATH_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }

    /// Spawn the background worker task and retain its `JoinHandle` so that
    /// `shutdown_and_wait` can await its completion. If a worker is already
    /// running, or if the service is disabled, this is a no-op.
    pub async fn spawn_worker(self: &Arc<Self>) {
        if !self.enabled {
            info!(
                "Secret Lifecycle service is disabled via LifecycleConfig.enabled; background worker will not be spawned"
            );
            return;
        }
        let mut guard = self.worker.lock().await;
        if guard.is_some() {
            return;
        }
        let handle = tokio::spawn(self.clone().start_worker());
        *guard = Some(handle);
    }

    /// Returns whether the service is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Signal the background worker to stop on its next tick.
    ///
    /// Uses `notify_one` so that if no task is currently awaiting
    /// `notified()` (e.g. the worker is busy inside `process_lifecycle_events`),
    /// a permit is stored and the next `notified()` call will complete
    /// immediately. `notify_waiters` would silently drop the signal in that case.
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// Signal shutdown and await the background worker's completion, so that
    /// any in-flight `process_lifecycle_events` call finishes before returning.
    pub async fn shutdown_and_wait(&self) {
        self.shutdown.notify_one();
        let handle = {
            let mut guard = self.worker.lock().await;
            guard.take()
        };
        if let Some(handle) = handle {
            if let Err(e) = handle.await {
                warn!("Lifecycle worker task did not shut down cleanly: {}", e);
            }
        }
    }

    /// Start the background lifecycle worker. Returns when `shutdown` is signalled.
    ///
    /// This is intentionally not `pub`: spawning the worker outside of
    /// `spawn_worker` would bypass `JoinHandle` tracking and prevent
    /// `shutdown_and_wait` from awaiting in-flight processing.
    async fn start_worker(self: Arc<Self>) {
        info!("Starting Secret Lifecycle background worker");
        // Delay the first tick by one period so that `process_lifecycle_events`
        // does not run immediately on startup. `tokio::time::interval` would
        // fire its first tick instantly, which is surprising for a destructive
        // periodic sweep and could interact badly with migrations/warm-up.
        let period = Duration::from_secs(3600);
        let mut ticker = interval_at(Instant::now() + period, period);
        let shutdown = self.shutdown.clone();

        loop {
            tokio::select! {
                // `biased;` ensures the shutdown branch is polled before the
                // ticker branch when both are ready. Without this, a concurrent
                // shutdown signal and ticker tick could non-deterministically
                // cause one final `process_lifecycle_events` run before exit.
                biased;
                _ = shutdown.notified() => {
                    info!("Secret Lifecycle background worker received shutdown signal");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.process_lifecycle_events().await {
                        error!("Error processing lifecycle events: {}", e);
                    }
                }
            }
        }
    }

    /// Process expired and expiring secrets
    pub async fn process_lifecycle_events(&self) -> Result<()> {
        // Defense-in-depth: honor the `enabled` flag even if the worker was
        // somehow started. This guards against the flag being flipped at runtime
        // or the service being driven from an external caller (e.g. tests).
        if !self.enabled {
            info!("Skipping lifecycle processing: service is disabled");
            return Ok(());
        }

        info!("Processing secret lifecycle events");

        // Scoped expiration cleanup with audit trail.
        //
        // Two properties this implementation guarantees (neither of which
        // `storage.delete_expired(None)` provides):
        //
        // 1. **Scope**: only user-owned secret entries are swept. Paths under
        //    reserved namespaces (`sys/`, `keys/`, `key_data/` — see
        //    `RESERVED_PATH_PREFIXES`) are skipped, so version history,
        //    policies, key material, audit logs, and backups are left to
        //    their own dedicated cleaners (e.g. `delete_expired_oauth_states`).
        // 2. **Audit trail**: every deletion emits a `SecretDeletion` audit
        //    event attributed to `LIFECYCLE_AUDIT_ACTOR`, matching the trail
        //    that user-initiated `SecretService::delete_secret` would produce.
        //
        // Gated by `cleanup_enabled` so operators can disable destructive
        // sweeps without having to also disable the whole lifecycle service.
        if self.cleanup_enabled {
            match self.sweep_expired_secrets().await {
                Ok(count) if count > 0 => {
                    info!("Successfully cleaned up {} expired secrets", count);
                }
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to clean up expired secrets: {}", e);
                    return Err(e);
                }
            }
        } else {
            info!("Skipping expired-secret sweep: cleanup_enabled is false");
        }

        // TODO: Implement real notification support (Email/Webhooks)
        // Integrate with CombinedMfaService or a dedicated NotificationService
        // to alert the secret owner or security team when a secret is expiring soon.

        // TODO: Integrate cloud secret synchronization (AWS Secrets Manager, Azure Key Vault)
        // using the modules available in secreton-integrations.
        // This will allow automatic rotation of cloud secrets synchronized with Secreton lifecycle policies.

        // 2. Cleanup internal manager state (for hooks/notifications tracking)
        if let Err(e) = self.manager.cleanup_expired().await {
            warn!("Failed to cleanup lifecycle manager state: {}", e);
        }

        Ok(())
    }

    pub fn manager(&self) -> Arc<SecretLifecycleManagement> {
        self.manager.clone()
    }

    /// Delete expired user-owned secret entries and emit a `SecretDeletion`
    /// audit event for each one.
    ///
    /// Entries under reserved namespaces (see `RESERVED_PATH_PREFIXES`) are
    /// skipped — those are owned by other subsystems with their own cleanup
    /// policies. Returns the number of entries actually deleted.
    ///
    /// Errors from individual deletions are logged but do not abort the sweep,
    /// so a single bad entry cannot block cleanup of the rest. A listing
    /// failure (which affects the whole sweep) is propagated.
    async fn sweep_expired_secrets(&self) -> Result<u64> {
        // Page through storage to bound peak memory usage on backends with
        // many entries. Without pagination, a single `list` call would pull
        // every entry into a `Vec<SecretEntry>` in memory each sweep.
        const PAGE_SIZE: u32 = 500;

        let mut deleted: u64 = 0;
        let mut offset: u32 = 0;

        loop {
            let params = QueryParams {
                include_expired: true,
                limit: Some(PAGE_SIZE),
                offset: Some(offset),
                ..Default::default()
            };

            let entries = self.storage.list(&params).await?;
            let page_len = entries.len() as u32;
            if page_len == 0 {
                break;
            }

            // Track skipped entries so we advance `offset` past non-deletable
            // rows (non-expired or reserved) on the next page. Deleted rows
            // shift subsequent entries back by one, so they don't contribute
            // to the offset.
            let mut skipped_this_page: u32 = 0;

            for entry in entries {
                if !entry.is_expired() {
                    skipped_this_page += 1;
                    continue;
                }
                if Self::is_reserved_path(&entry.path) {
                    skipped_this_page += 1;
                    continue;
                }

                match self.storage.delete_by_id(entry.id).await {
                    Ok(true) => {
                        deleted += 1;
                        // Emit audit event. `log_event` is infallible (buffers
                        // internally and logs on flush failures) so there's no
                        // Result to propagate here.
                        self.audit
                            .log_event(SecurityEventType::SecretDeletion {
                                secret_path: entry.path.clone(),
                                user: LIFECYCLE_AUDIT_ACTOR.to_string(),
                            })
                            .await;
                    }
                    Ok(false) => {
                        // Entry vanished between list and delete — benign race.
                    }
                    Err(e) => {
                        // Count as skipped so we don't re-fetch the same
                        // failing entry forever on the next page.
                        skipped_this_page += 1;
                        warn!(
                            "Failed to delete expired secret at path {}: {}",
                            entry.path, e
                        );
                    }
                }
            }

            if page_len < PAGE_SIZE {
                break;
            }
            offset = offset.saturating_add(skipped_this_page);
        }

        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::crypto::CryptoService;
    use crate::services::secret::SecretService;
    use secreton_auth::policies::service::PolicyService;
    use secreton_auth::{IdentityService, InMemoryIdentityService};
    use secreton_performance::{SecretPerformanceConfig, SecretPerformanceOptimizer};
    use secreton_storage::memory::InMemoryStorage;

    async fn make_service(enabled: bool, cleanup_enabled: bool) -> Arc<LifecycleService> {
        let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(InMemoryStorage::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            crate::services::audit::AuditLogger::new(storage.clone(), 30, 100, false)
                .await
                .unwrap(),
        );
        let identity: Arc<dyn IdentityService + Send + Sync> =
            Arc::new(InMemoryIdentityService::new());
        let policy = Arc::new(PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::new(
            SecretPerformanceConfig::default(),
        ));
        let secreton = Arc::new(
            SecretService::new(
                storage.clone(),
                crypto.clone(),
                audit.clone(),
                identity,
                policy,
                performance,
            )
            .await
            .unwrap(),
        );
        let cfg = LifecycleConfig {
            enabled,
            default_ttl_days: 90,
            grace_period_days: 7,
            auto_archive_enabled: false,
            cleanup_enabled,
        };
        Arc::new(LifecycleService::new(storage, secreton, audit, cfg))
    }

    #[tokio::test]
    async fn disabled_service_skips_processing() {
        let svc = make_service(false, true).await;
        assert!(!svc.is_enabled());
        // Should be a no-op Ok(()) — defense-in-depth check.
        svc.process_lifecycle_events().await.unwrap();
    }

    #[tokio::test]
    async fn disabled_service_does_not_spawn_worker() {
        let svc = make_service(false, true).await;
        svc.spawn_worker().await;
        let guard = svc.worker.lock().await;
        assert!(guard.is_none());
    }

    #[tokio::test]
    async fn spawn_worker_is_idempotent() {
        let svc = make_service(true, false).await;
        svc.spawn_worker().await;
        svc.spawn_worker().await;
        {
            let guard = svc.worker.lock().await;
            assert!(guard.is_some());
        }
        svc.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn shutdown_and_wait_terminates_worker() {
        let svc = make_service(true, false).await;
        svc.spawn_worker().await;
        svc.shutdown_and_wait().await;
        let guard = svc.worker.lock().await;
        assert!(guard.is_none());
    }

    #[tokio::test]
    async fn cleanup_disabled_skips_storage_delete() {
        let svc = make_service(true, false).await;
        // With cleanup_enabled=false the storage sweep is skipped;
        // process_lifecycle_events should still succeed.
        svc.process_lifecycle_events().await.unwrap();
    }

    #[tokio::test]
    async fn sweep_skips_reserved_paths_and_deletes_user_secrets() {
        use chrono::{Duration as ChronoDuration, Utc};
        use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel};
        use uuid::Uuid;

        let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(InMemoryStorage::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            crate::services::audit::AuditLogger::new(storage.clone(), 30, 100, false)
                .await
                .unwrap(),
        );
        let identity: Arc<dyn IdentityService + Send + Sync> =
            Arc::new(InMemoryIdentityService::new());
        let policy = Arc::new(PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::new(
            SecretPerformanceConfig::default(),
        ));
        let secreton = Arc::new(
            SecretService::new(
                storage.clone(),
                crypto.clone(),
                audit.clone(),
                identity,
                policy,
                performance,
            )
            .await
            .unwrap(),
        );

        let owner = Uuid::new_v4();
        let past = Utc::now() - ChronoDuration::hours(1);

        // Expired user-owned secret — should be deleted.
        let user_entry = SecretEntry::new(
            "app/prod/api-key".to_string(),
            vec![1, 2, 3],
            EncryptionMetadata::default(),
            SecurityLevel::Confidential,
            owner,
        )
        .with_expiration(past);
        storage.store(&user_entry).await.unwrap();

        // Expired entry under a reserved namespace — must be preserved.
        let reserved_entry = SecretEntry::new(
            "sys/history/app/prod/api-key::v1".to_string(),
            vec![9, 9, 9],
            EncryptionMetadata::default(),
            SecurityLevel::Confidential,
            owner,
        )
        .with_expiration(past);
        storage.store(&reserved_entry).await.unwrap();

        let cfg = LifecycleConfig {
            enabled: true,
            default_ttl_days: 90,
            grace_period_days: 7,
            auto_archive_enabled: false,
            cleanup_enabled: true,
        };
        let svc = Arc::new(LifecycleService::new(
            storage.clone(),
            secreton,
            audit,
            cfg,
        ));

        svc.process_lifecycle_events().await.unwrap();

        // User secret is gone.
        assert!(
            storage
                .get_by_path("app/prod/api-key")
                .await
                .unwrap()
                .is_none(),
            "expired user secret should be deleted"
        );
        // Reserved-namespace entry is preserved.
        assert!(
            storage
                .get_by_path("sys/history/app/prod/api-key::v1")
                .await
                .unwrap()
                .is_some(),
            "entries under sys/ must not be swept by the lifecycle worker"
        );
    }
}

