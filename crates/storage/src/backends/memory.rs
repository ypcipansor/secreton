//! In-memory storage backend.

use async_trait::async_trait;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use secreton_domain::OAuthState;

use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageFence,
    StorageResult, StorageStats, StorageTransaction,
};

/// In-memory storage backend.
///
/// Always compiled, with no external service required, so `cargo leptos serve`, the test
/// suite and a first-run demo all work with zero setup. State lives only for the lifetime
/// of the process — it is not a production backend.
#[derive(Debug, Clone)]
pub struct MemoryBackend {
    data: Arc<RwLock<HashMap<String, SecretEntry>>>,
    id_index: Arc<RwLock<HashMap<Uuid, String>>>,
    oauth_states: Arc<RwLock<HashMap<String, OAuthState>>>,
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            id_index: Arc::new(RwLock::new(HashMap::new())),
            oauth_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl StorageBackend for MemoryBackend {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut data = self.data.write();
        let mut id_index = self.id_index.write();

        data.insert(entry.path.clone(), entry.clone());
        id_index.insert(entry.id, entry.path.clone());

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let id_index = self.id_index.read();
        if let Some(path) = id_index.get(&id) {
            let data = self.data.read();
            Ok(data.get(path).cloned())
        } else {
            Ok(None)
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let data = self.data.read();
        Ok(data.get(path).cloned())
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut data = self.data.write();
        if data.contains_key(&entry.path) {
            data.insert(entry.path.clone(), entry.clone());
            Ok(())
        } else {
            Err(StorageError::NotFound {
                resource_type: "SecretEntry".to_string(),
                id: entry.id.to_string(),
            })
        }
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let mut id_index = self.id_index.write();
        if let Some(path) = id_index.remove(&id) {
            let mut data = self.data.write();
            if data.remove(&path).is_some() {
                Ok(true)
            } else {
                // restore index consistency if data missing unexpectedly
                id_index.insert(id, path);
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let mut data = self.data.write();
        if let Some(entry) = data.remove(path) {
            let mut id_index = self.id_index.write();
            id_index.remove(&entry.id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Atomic within this backend's own lock: the check and the write happen while the
    /// same `RwLock` write guard is held, so no other task on this instance can observe
    /// the path between them. Two `MemoryBackend`s are two separate maps, so this is
    /// in-process only by construction — which is all a process-local backend can offer.
    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: crate::Expect<'_>,
    ) -> StorageResult<bool> {
        let mut data = self.data.write();
        let existing = data.get(&entry.path);

        let holds = match expect {
            crate::Expect::Absent => existing.is_none(),
            crate::Expect::Owner(token) => existing.is_some_and(|e| e.has_owner(token)),
            crate::Expect::Any => true,
        };
        if !holds {
            return Ok(false);
        }

        // A replacement keeps the existing record's id and creation time, matching
        // [`StorageBackend::upsert`]: the path is the identity that matters and callers
        // that go on to `update` are keyed by id on PostgreSQL.
        let to_write = match existing {
            Some(old) => {
                let mut updated = entry.clone();
                updated.id = old.id;
                updated.created_at = old.created_at;
                updated
            }
            None => entry.clone(),
        };
        let mut id_index = self.id_index.write();
        if let Some(old) = existing {
            let old_id = old.id;
            id_index.remove(&old_id);
        }
        id_index.insert(to_write.id, to_write.path.clone());
        data.insert(to_write.path.clone(), to_write);
        Ok(true)
    }

    async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
        let mut data = self.data.write();
        let owned = data.get(path).is_some_and(|e| e.has_owner(token));
        if !owned {
            return Ok(false);
        }
        let entry = data.remove(path).expect("just checked present");
        self.id_index.write().remove(&entry.id);
        Ok(true)
    }

    /// Atomic within this backend's own lock, which is the whole guarantee a process-local
    /// map can offer. The fence record and the write are evaluated under the same write
    /// guard, so no task on this instance can observe the path between them and no caller
    /// whose fence token no longer matches can publish anything.
    async fn store_fenced(
        &self,
        entry: &SecretEntry,
        fence: StorageFence<'_>,
    ) -> StorageResult<bool> {
        let mut data = self.data.write();
        if !data
            .get(fence.path)
            .is_some_and(|e| e.has_owner(fence.token))
        {
            return Ok(false);
        }

        let existing = data.get(&entry.path).cloned();
        let to_write = match existing {
            Some(old) => {
                let mut updated = entry.clone();
                updated.id = old.id;
                updated.created_at = old.created_at;
                updated
            }
            None => entry.clone(),
        };
        let mut id_index = self.id_index.write();
        if let Some(old) = data.get(&entry.path) {
            id_index.remove(&old.id);
        }
        id_index.insert(to_write.id, to_write.path.clone());
        data.insert(to_write.path.clone(), to_write);
        Ok(true)
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let data = self.data.read();
        let mut results: Vec<SecretEntry> = data
            .values()
            .filter(|entry| {
                // Simple filtering logic
                if let Some(prefix) = &params.path_prefix
                    && !entry.path.starts_with(prefix)
                {
                    return false;
                }
                if let Some(owner) = params.owner_id
                    && entry.owner_id != owner
                {
                    return false;
                }
                !entry.is_expired() || params.include_expired
            })
            .cloned()
            .collect();

        // Apply limit
        if let Some(limit) = params.limit {
            results.truncate(limit as usize);
        }

        Ok(results)
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let entries = self.list(params).await?;
        Ok(entries.len() as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let data = self.data.read();
        Ok(data.contains_key(path))
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(MemoryTransaction::new(self.clone())))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        Ok(HealthStatus {
            is_healthy: true,
            response_time_ms: 1.0,
            connections_active: 1,
            connections_idle: 0,
            last_error: None,
            uptime_seconds: 3600,
        })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        let data = self.data.read();
        let total_entries = data.len() as u64;
        let total_size_bytes = data.values().map(|e| e.encrypted_data.len() as u64).sum();

        Ok(StorageStats {
            total_entries,
            total_size_bytes,
            average_entry_size: if total_entries > 0 {
                total_size_bytes as f64 / total_entries as f64
            } else {
                0.0
            },
            entries_by_security_level: HashMap::new(),
            entries_created_today: total_entries,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        // Mock migration - nothing to do
        Ok(())
    }

    async fn compact(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn vacuum(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
        let now = Utc::now();
        let mut data = self.data.write();
        let mut id_index = self.id_index.write();
        let mut deleted_count = 0;

        // Collect keys to delete first to avoid borrowing issues
        let keys_to_delete: Vec<String> = data
            .iter()
            .filter(|(_, entry)| {
                let matches_prefix = if let Some(prefix) = &path_prefix {
                    entry.path.starts_with(prefix)
                } else {
                    true
                };

                let is_expired = if let Some(expires_at) = entry.expires_at {
                    expires_at < now
                } else {
                    false
                };

                matches_prefix && is_expired
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in keys_to_delete {
            if let Some(entry) = data.remove(&key) {
                id_index.remove(&entry.id);
                deleted_count += 1;
            }
        }

        Ok(deleted_count)
    }

    async fn store_oauth_state(&self, state: &OAuthState) -> StorageResult<()> {
        let mut states = self.oauth_states.write();
        states.insert(state.state.clone(), state.clone());
        Ok(())
    }

    async fn get_oauth_state(&self, state: &str) -> StorageResult<Option<OAuthState>> {
        let mut states = self.oauth_states.write();
        if let Some(oauth_state) = states.get(state)
            && oauth_state.expires_at < Utc::now()
        {
            states.remove(state);
            return Ok(None);
        }
        Ok(states.remove(state))
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        let mut states = self.oauth_states.write();
        let mut count = 0;
        states.retain(|_, state| {
            if state.expires_at < Utc::now() {
                count += 1;
                false
            } else {
                true
            }
        });
        Ok(count)
    }
}

/// Transaction over [`MemoryBackend`].
///
/// The previous implementation returned a transaction whose methods were all `Ok(())`
/// no-ops, so callers that wrote through `begin_transaction` silently lost every write
/// while being told it had succeeded. This buffers the operations and applies them on
/// `commit`, so a caller that commits sees its writes and a caller that rolls back
/// sees none of them.
#[derive(Debug)]
pub struct MemoryTransaction {
    backend: MemoryBackend,
    pending: Vec<PendingOp>,
}

#[derive(Debug)]
enum PendingOp {
    Store(Box<SecretEntry>),
    Update(Box<SecretEntry>),
    Delete(Uuid),
}

impl MemoryTransaction {
    fn new(backend: MemoryBackend) -> Self {
        Self {
            backend,
            pending: Vec::new(),
        }
    }
}

#[async_trait]
impl StorageTransaction for MemoryTransaction {
    async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        self.pending.push(PendingOp::Store(Box::new(entry.clone())));
        Ok(())
    }

    async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        self.pending
            .push(PendingOp::Update(Box::new(entry.clone())));
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        self.pending.push(PendingOp::Delete(id));
        Ok(true)
    }

    async fn commit(self: Box<Self>) -> StorageResult<()> {
        for op in &self.pending {
            match op {
                PendingOp::Store(entry) => self.backend.store(entry).await?,
                PendingOp::Update(entry) => self.backend.update(entry).await?,
                PendingOp::Delete(id) => {
                    self.backend.delete_by_id(*id).await?;
                }
            }
        }
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> StorageResult<()> {
        // Nothing was applied, so dropping the buffer is the rollback.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionMetadata, SecurityLevel};

    fn entry(path: &str) -> SecretEntry {
        SecretEntry::new(
            path.to_string(),
            vec![1, 2, 3],
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "key-1".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Internal,
            Uuid::new_v4(),
        )
    }

    #[tokio::test]
    async fn store_and_read_round_trip() {
        let backend = MemoryBackend::new();
        let e = entry("kv/app/db");
        backend.store(&e).await.unwrap();

        assert_eq!(
            backend.get_by_path("kv/app/db").await.unwrap().unwrap().id,
            e.id
        );
        assert_eq!(backend.get_by_id(e.id).await.unwrap().unwrap().path, e.path);
        assert!(backend.exists("kv/app/db").await.unwrap());
    }

    #[tokio::test]
    async fn committed_transaction_writes_are_visible() {
        let backend = MemoryBackend::new();
        let e = entry("kv/tx/committed");

        let mut tx = backend.begin_transaction().await.unwrap();
        tx.store(&e).await.unwrap();
        tx.commit().await.unwrap();

        assert!(
            backend
                .get_by_path("kv/tx/committed")
                .await
                .unwrap()
                .is_some(),
            "a committed transaction must persist its writes"
        );
    }

    #[tokio::test]
    async fn rolled_back_transaction_writes_are_discarded() {
        let backend = MemoryBackend::new();
        let e = entry("kv/tx/rolled-back");

        let mut tx = backend.begin_transaction().await.unwrap();
        tx.store(&e).await.unwrap();
        tx.rollback().await.unwrap();

        assert!(
            backend
                .get_by_path("kv/tx/rolled-back")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn deleting_by_path_also_clears_the_id_index() {
        let backend = MemoryBackend::new();
        let e = entry("kv/app/gone");
        backend.store(&e).await.unwrap();

        assert!(backend.delete_by_path("kv/app/gone").await.unwrap());
        assert!(backend.get_by_id(e.id).await.unwrap().is_none());
        assert!(!backend.delete_by_path("kv/app/gone").await.unwrap());
    }

    #[tokio::test]
    async fn oauth_state_is_single_use_and_expires() {
        use chrono::Duration;

        let backend = MemoryBackend::new();
        let live = OAuthState {
            state: "live".into(),
            provider: "github".into(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        backend.store_oauth_state(&live).await.unwrap();

        assert!(backend.get_oauth_state("live").await.unwrap().is_some());
        assert!(
            backend.get_oauth_state("live").await.unwrap().is_none(),
            "an OAuth state must not be redeemable twice"
        );

        let stale = OAuthState {
            state: "stale".into(),
            provider: "github".into(),
            created_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::hours(1),
        };
        backend.store_oauth_state(&stale).await.unwrap();
        assert!(backend.get_oauth_state("stale").await.unwrap().is_none());
    }
}
