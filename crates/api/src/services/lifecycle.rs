//! Lifecycle service for managing secret expiration and archival.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{Duration, interval};
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
        Self {
            storage,
            _secreton: secreton,
            manager: Arc::new(SecretLifecycleManagement::new(config)),
            shutdown: Arc::new(Notify::new()),
            enabled,
            worker: Mutex::new(None),
        }
    }

    /// Spawn the background worker task and retain its `JoinHandle` so that
    /// `shutdown_and_wait` can await its completion. If a worker is already
    /// running, this is a no-op.
    pub async fn spawn_worker(self: &Arc<Self>) {
        let mut guard = self.worker.lock().await;
        if guard.is_some() {
            return;
        }
        let handle = tokio::spawn(self.clone().start_worker());
        *guard = Some(handle);
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
        let mut ticker = interval(Duration::from_secs(3600)); // Run every hour
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
