//! Lifecycle service for managing secret expiration and archival.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Notify;
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
}

impl LifecycleService {
    pub fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        secreton: Arc<SecretService>,
        config: LifecycleConfig,
    ) -> Self {
        Self {
            storage,
            _secreton: secreton,
            manager: Arc::new(SecretLifecycleManagement::new(config)),
            shutdown: Arc::new(Notify::new()),
        }
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

    /// Start the background lifecycle worker. Returns when `shutdown` is signalled.
    pub async fn start_worker(self: Arc<Self>) {
        info!("Starting Secret Lifecycle background worker");
        let mut ticker = interval(Duration::from_secs(3600)); // Run every hour
        let shutdown = self.shutdown.clone();

        loop {
            tokio::select! {
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
