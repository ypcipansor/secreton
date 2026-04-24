//! Lifecycle service for managing secret expiration and archival.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, interval_at};
use tracing::{error, info, warn};

use crate::services::secret::SecretService;
use secreton_integrations::integrations::secret_lifecycle_management::{
    LifecycleConfig, SecretLifecycleManagement,
};
use secreton_storage::StorageBackend;

pub struct LifecycleService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    _secreton: Arc<SecretService>,
    manager: Arc<SecretLifecycleManagement>,
    shutdown: Arc<Notify>,
    enabled: bool,
    /// When false, `process_lifecycle_events` skips the destructive
    /// `storage.delete_expired` sweep. Mirrors `LifecycleConfig.cleanup_enabled`
    /// so that the flag gates the primary cleanup path (not just the
    /// secondary in-memory manager cleanup).
    cleanup_enabled: bool,
    /// Handle for the background worker task, stored so that shutdown can
    /// await its completion and ensure any in-flight processing finishes.
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl LifecycleService {
    pub fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        secreton: Arc<SecretService>,
        config: LifecycleConfig,
    ) -> Self {
        let enabled = config.enabled;
        let cleanup_enabled = config.cleanup_enabled;
        Self {
            storage,
            _secreton: secreton,
            manager: Arc::new(SecretLifecycleManagement::new(config)),
            shutdown: Arc::new(Notify::new()),
            enabled,
            cleanup_enabled,
            worker: Mutex::new(None),
        }
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

        // Use the storage backend's built-in expiration cleanup.
        // This performs the actual deletion of expired entries from the database.
        // Gated by `cleanup_enabled` so operators can disable destructive
        // sweeps without having to also disable the whole lifecycle service.
        //
        // TODO: Scope this sweep to the secrets path prefix instead of `None`.
        // Passing `None` deletes every expired entry across storage, which can
        // overlap with dedicated cleaners (e.g. `delete_expired_oauth_states`)
        // and deletes unrelated ephemeral entries.
        //
        // TODO: Emit a `SecretDeletion` (or dedicated `LifecycleExpiration`)
        // audit event for each deleted entry. Direct `storage.delete_expired`
        // bypasses the audit trail that `SecretService::delete_secret` would
        // otherwise produce — unacceptable long-term for a secrets manager.
        if self.cleanup_enabled {
            match self.storage.delete_expired(None).await {
                Ok(count) if count > 0 => {
                    info!("Successfully cleaned up {} expired secrets", count);
                }
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to clean up expired secrets: {}", e);
                    return Err(e.into());
                }
            }
        } else {
            info!("Skipping storage.delete_expired: cleanup_enabled is false");
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
                audit,
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
        Arc::new(LifecycleService::new(storage, secreton, cfg))
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
}

