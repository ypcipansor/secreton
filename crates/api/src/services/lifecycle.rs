//! Lifecycle service for managing secret expiration and archival.

use anyhow::Result;
use std::sync::{Arc, Weak};
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
//
// Defense-in-depth: in addition to the `sys/`, `keys/`, and `key_data/`
// namespaces, we also reserve prefixes used by other API services
// (`sessions/`, `users/`, `db/`, `totp/`, `pki/`, `auth/`, `mfa/`). These
// services manage their own entry lifecycles (e.g. session expiration,
// dynamic database lease revocation, TOTP secret rotation) and could store
// entries with `expires_at` set for purposes other than user-secret cleanup.
// Sweeping them from this worker would race with their owning subsystems.
//
// We also reserve `policies/`, `backups/`, and `config/` as additional
// top-level subsystem namespaces. These are not currently expected to
// carry `expires_at`, so they are unreachable in practice today, but
// listing them explicitly avoids the "exclusion depends on assumption"
// failure mode if a future change ever sets a TTL on a policy or backup
// entry — for example, a transient scheduled-deletion policy would be
// silently swept here without this entry.
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
        // Hand the worker a `Weak<Self>` rather than a strong `Arc`. Otherwise
        // the spawned task would keep the `LifecycleService` alive forever:
        // even if every external `Arc<LifecycleService>` is dropped (e.g. an
        // owning container is dropped without anyone calling
        // `stop_services()` / `shutdown_and_wait()`), the worker's strong
        // reference would prevent the service from being dropped and the
        // hourly sweep would keep running until process exit. With `Weak`,
        // the worker exits naturally once no external owner remains.
        let weak = Arc::downgrade(self);
        let handle = tokio::spawn(start_worker(weak));
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

    /// Snapshot the `Notify` handle without holding a strong `Arc<Self>`.
    /// Used by the worker (which holds a `Weak<Self>`) so that it can await
    /// shutdown signals even when no strong reference is currently held.
    fn shutdown_handle(&self) -> Arc<Notify> {
        self.shutdown.clone()
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
        // Single-pass sweep with a safety bound.
        //
        // We previously paginated via `QueryParams.offset`, but most production
        // backends (PostgreSQL, MySQL, CockroachDB, and the in-memory mock)
        // silently ignore `offset` — only the File and Raft backends honor it.
        // That made offset-based pagination fragile at best: on offset-ignoring
        // backends the sweep either looped forever (pre-fix) or bailed out
        // after the first page (with the duplicate-ID guard), leaving expired
        // entries beyond `PAGE_SIZE` uncleaned indefinitely.
        //
        // Note on scope: `QueryParams.include_expired = true` means "do not
        // filter out expired entries from the result" — it does NOT mean
        // "return only expired entries". As a result, `list(...)` returns
        // every entry the backend stores (both expired and non-expired) and
        // we filter for `is_expired()` in the loop below. Combined with the
        // PostgreSQL backend no longer imposing a default `LIMIT 100`, this
        // means an unbounded sweep could load the entire secrets table into
        // memory on a large deployment. We mitigate that with an explicit
        // `SWEEP_MAX_ENTRIES` cap: if the backend has more entries than the
        // cap, only the first `SWEEP_MAX_ENTRIES` are considered per tick
        // and the rest will be picked up on subsequent ticks. This is a
        // conservative safety bound, not a correctness guarantee.
        //
        // The right long-term fix is a backend-level "only expired" query
        // (e.g. a new `QueryParams.only_expired` flag with backend support,
        // or a dedicated `list_expired()` method), which would let us pull
        // just the rows we intend to delete. Tracked as a TODO below.
        //
        // TODO: Add backend-level filtering so only expired entries are
        // returned, avoiding the need to load non-expired rows into memory.
        const SWEEP_MAX_ENTRIES: u32 = 10_000;

        // Sort by `expires_at ASC` so that already-expired entries (the rows
        // we actually intend to delete) come first within the
        // `SWEEP_MAX_ENTRIES` window. The default ordering on the PostgreSQL
        // backend is `created_at DESC` (newest first), which on a deployment
        // with more than `SWEEP_MAX_ENTRIES` non-expired-but-newer entries
        // would push every expired entry past the cap and leave them
        // uncleaned indefinitely. The PostgreSQL backend translates this to
        // `ORDER BY expires_at ASC NULLS LAST` so non-expiring rows sort to
        // the end. The MySQL backend honors `sort_by`/`sort_order` as well
        // (using `COALESCE(expires_at, '9999-12-31') ASC` to emulate
        // `NULLS LAST`). Backends that ignore `sort_by` (e.g. the in-memory
        // mock) are unaffected by this hint.
        //
        // Push reserved-namespace exclusion down to the storage layer via
        // `excluded_path_prefixes`. This prevents reserved entries (notably
        // `sys/audit/` rows, which carry `expires_at` and accumulate
        // indefinitely without a dedicated cleaner) from consuming rows
        // from the `limit` budget and starving user-secret cleanup. The
        // in-memory `is_reserved_path` check below remains as defense-in-depth
        // for backends that ignore this field.
        let params = QueryParams {
            include_expired: true,
            limit: Some(SWEEP_MAX_ENTRIES),
            sort_by: Some("expires_at".to_string()),
            sort_order: Some("asc".to_string()),
            excluded_path_prefixes: RESERVED_PATH_PREFIXES
                .iter()
                .map(|p| (*p).to_string())
                .collect(),
            ..Default::default()
        };

        let entries = self.storage.list(&params).await?;
        let mut deleted: u64 = 0;

        for entry in entries {
            if !entry.is_expired() {
                continue;
            }
            if Self::is_reserved_path(&entry.path) {
                continue;
            }

            // TOCTOU guard: re-read the entry immediately before deleting and
            // re-check `is_expired()`. The `entries` vec is a stale snapshot
            // from the `list()` call above; between that call and the
            // `delete_by_id` below, the user may have renewed (extended
            // `expires_at`) or rotated the secret. Without this re-check we
            // would silently delete a just-renewed secret — a data-loss bug
            // for the user whose renewal appeared to succeed.
            //
            // This narrows the race window from "duration of the whole sweep"
            // down to "between `get_by_id` and `delete_by_id`". A fully
            // race-free fix requires a conditional `DELETE ... WHERE id = $1
            // AND expires_at < NOW()` at the storage layer, which the current
            // `StorageBackend` trait does not expose. Tracked as a TODO.
            //
            // TODO: Add a conditional delete (e.g. `delete_if_expired`) to
            // the `StorageBackend` trait so this guard can be made atomic.
            let fresh = match self.storage.get_by_id(entry.id).await {
                Ok(Some(e)) => e,
                Ok(None) => {
                    // Entry vanished between list and re-read — benign race.
                    continue;
                }
                Err(e) => {
                    warn!(
                        "Failed to re-read expired secret at path {} before delete: {}",
                        entry.path, e
                    );
                    continue;
                }
            };
            if !fresh.is_expired() {
                // Renewed between list and re-read — preserve it.
                continue;
            }

            match self.storage.delete_by_id(fresh.id).await {
                Ok(true) => {
                    deleted += 1;
                    // Emit audit event. `log_event` is infallible (buffers
                    // internally and logs on flush failures) so there's no
                    // Result to propagate here.
                    self.audit
                        .log_event(SecurityEventType::SecretDeletion {
                            secret_path: fresh.path.clone(),
                            user: LIFECYCLE_AUDIT_ACTOR.to_string(),
                        })
                        .await;

                    // Clean up version history entries scoped to this secret.
                    //
                    // `SecretService::put_secret` archives prior versions to
                    // `sys/history/{path}::v{N}` and `SecretService::delete_secret`
                    // (the user-initiated path) deletes them as part of the
                    // delete operation (see `crates/api/src/services/secret.rs`
                    // around the `HISTORY_DELETE_MAX_ENTRIES` block). Without
                    // an equivalent cleanup here, expired secrets swept by the
                    // lifecycle worker would leave orphaned encrypted history
                    // entries indefinitely: those entries live under `sys/`,
                    // which is in `RESERVED_PATH_PREFIXES`, so they will never
                    // be picked up by a future sweep tick.
                    //
                    // The history-prefix scan is scoped to a specific just-
                    // deleted user secret's path, so it does not violate the
                    // reserved-namespace contract — we are only removing
                    // entries that belong to a secret we just removed.
                    self.cleanup_history_for(&fresh.path).await;
                }
                Ok(false) => {
                    // Entry vanished between re-read and delete — benign race.
                }
                Err(e) => {
                    warn!(
                        "Failed to delete expired secret at path {}: {}",
                        fresh.path, e
                    );
                }
            }
        }

        Ok(deleted)
    }

    /// Delete `sys/history/{path}::v*` entries for a secret that was just
    /// swept. Errors are logged but do not abort the sweep — leaving a
    /// history entry behind is recoverable; aborting the sweep is not.
    async fn cleanup_history_for(&self, path: &str) {
        // Mirrors the bound used by `SecretService::delete_secret`'s history
        // cleanup. 10k history entries for a single secret is far above
        // realistic usage; capping prevents the lifecycle worker from
        // scanning arbitrary numbers of rows on a single deletion.
        const HISTORY_DELETE_MAX_ENTRIES: u32 = 10_000;

        let history_prefix = format!("sys/history/{}::v", path);
        // `include_expired: true` is critical here. History entries are stored
        // via `SecretService::put_secret` as a clone of the parent secret
        // (`existing.clone()` in `crates/api/src/services/secret.rs`), which
        // means they inherit the parent's `expires_at`. By the time the
        // lifecycle sweep is deleting an expired parent, those history
        // entries are necessarily also past their `expires_at`. With the
        // default `include_expired: false`, the PostgreSQL backend's
        // expiration filter (`AND (expires_at IS NULL OR expires_at > NOW())`)
        // would silently drop them from this query — leaving orphaned
        // history rows under `sys/history/` that no future sweep can ever
        // reach (the `sys/` namespace is reserved).
        let query = QueryParams {
            path_prefix: Some(history_prefix),
            limit: Some(HISTORY_DELETE_MAX_ENTRIES),
            include_expired: true,
            ..Default::default()
        };

        let entries = match self.storage.list(&query).await {
            Ok(entries) => entries,
            Err(e) => {
                warn!(
                    "Failed to list history entries for swept secret {}: {}",
                    path, e
                );
                return;
            }
        };

        for entry in entries {
            if let Err(e) = self.storage.delete_by_id(entry.id).await {
                warn!(
                    "Failed to delete orphaned history entry {} for swept secret {}: {}",
                    entry.path, path, e
                );
            }
        }
    }
}

/// Background worker driver. Holds only a `Weak<LifecycleService>` so that
/// the worker does not keep the service alive on its own — once every
/// external `Arc<LifecycleService>` is dropped, `weak.upgrade()` returns
/// `None` and the worker exits. This makes ungraceful shutdowns safe: even
/// if `shutdown_and_wait()` is never called, the worker terminates as soon
/// as its owner is dropped, instead of leaking a periodic sweep until
/// process exit.
async fn start_worker(weak: Weak<LifecycleService>) {
    info!("Starting Secret Lifecycle background worker");
    // Snapshot the `Notify` while we still have a strong reference. The
    // owner can later signal shutdown through this handle even after the
    // worker only holds a `Weak`, because `Notify` is independently `Arc`'d.
    let shutdown = match weak.upgrade() {
        Some(svc) => svc.shutdown_handle(),
        None => return,
    };

    // Delay the first tick by one period so that `process_lifecycle_events`
    // does not run immediately on startup. `tokio::time::interval` would
    // fire its first tick instantly, which is surprising for a destructive
    // periodic sweep and could interact badly with migrations/warm-up.
    let period = Duration::from_secs(3600);
    let mut ticker = interval_at(Instant::now() + period, period);

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
                // Only upgrade for the duration of one tick. If the service
                // has been dropped, exit cleanly without running the sweep.
                let Some(svc) = weak.upgrade() else {
                    info!("Secret Lifecycle service dropped; worker exiting");
                    break;
                };
                if let Err(e) = svc.process_lifecycle_events().await {
                    error!("Error processing lifecycle events: {}", e);
                }
                // `svc` (strong Arc) goes out of scope here, so we don't
                // pin the service alive between ticks.
            }
        }
    }
}

impl Drop for LifecycleService {
    /// Defense-in-depth: signal the background worker on drop so it stops
    /// promptly even when callers forget to invoke `shutdown_and_wait()`.
    /// The worker's `Weak<Self>` will also fail to upgrade on the next
    /// tick, but `notify_one` makes the exit immediate rather than
    /// waiting up to one period for the next tick.
    fn drop(&mut self) {
        self.shutdown.notify_one();
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
    use secreton_storage::MockStorageBackend;

    async fn make_service(enabled: bool, cleanup_enabled: bool) -> Arc<LifecycleService> {
        let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(MockStorageBackend::new());
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

        let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(MockStorageBackend::new());
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

        // History entry belonging to the secret being swept — should be
        // cleaned up alongside the primary entry to prevent orphaned
        // encrypted history rows from accumulating under `sys/history/`.
        // No `expires_at` is set: history entries are removed because their
        // owning secret is being deleted, not because they expired
        // independently.
        let history_entry = SecretEntry::new(
            "sys/history/app/prod/api-key::v1".to_string(),
            vec![9, 9, 9],
            EncryptionMetadata::default(),
            SecurityLevel::Confidential,
            owner,
        );
        storage.store(&history_entry).await.unwrap();

        // Unrelated entry under a reserved namespace (different secret) —
        // must be preserved. This proves the reserved-namespace guard is
        // still honored for entries that are not history of a swept secret.
        let unrelated_reserved = SecretEntry::new(
            "sys/history/other/secret::v1".to_string(),
            vec![7, 7, 7],
            EncryptionMetadata::default(),
            SecurityLevel::Confidential,
            owner,
        )
        .with_expiration(past);
        storage.store(&unrelated_reserved).await.unwrap();

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
        // History entry for the swept secret is also gone — otherwise it
        // would be an orphaned `sys/history/` row that no future sweep can
        // ever reach (the `sys/` namespace is reserved).
        assert!(
            storage
                .get_by_path("sys/history/app/prod/api-key::v1")
                .await
                .unwrap()
                .is_none(),
            "history entries of a swept secret must be cleaned up to avoid orphans"
        );
        // Unrelated reserved-namespace entry is preserved — the lifecycle
        // worker still does not touch reserved entries that don't belong to
        // a secret it just deleted.
        assert!(
            storage
                .get_by_path("sys/history/other/secret::v1")
                .await
                .unwrap()
                .is_some(),
            "unrelated entries under sys/ must not be swept by the lifecycle worker"
        );
    }
}

