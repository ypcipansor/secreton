//! Modern Redis storage backend implementation using redis v0.1.0-alpha.1

use crate::{
    Coordination, HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError,
    StorageResult, StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use chrono::Utc;
use redis::{AsyncCommands, Client, aio::ConnectionManager};
use secreton_domain::OAuthState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Modern Redis storage backend with connection pooling
pub struct RedisBackend {
    manager: Arc<Mutex<ConnectionManager>>,
}

/// Redis transaction implementation using pipelines
pub struct RedisTransaction {
    manager: Arc<Mutex<ConnectionManager>>,
    operations: Vec<RedisTransactionOp>,
    committed: bool,
}

#[derive(Debug, Clone)]
enum RedisTransactionOp {
    Store(SecretEntry),
    Update(SecretEntry),
    Delete(Uuid),
}

impl RedisTransaction {
    pub fn new(manager: Arc<Mutex<ConnectionManager>>) -> Self {
        Self {
            manager,
            operations: Vec::new(),
            committed: false,
        }
    }
}

#[async_trait]
impl StorageTransaction for RedisTransaction {
    async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(RedisTransactionOp::Store(entry.clone()));
        Ok(())
    }

    async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(RedisTransactionOp::Update(entry.clone()));
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(RedisTransactionOp::Delete(id));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // Get Redis connection from backend and execute all operations
        let mut conn = self.manager.lock().await;
        let mut pipe = redis::pipe();
        pipe.atomic();

        for op in self.operations {
            match op {
                RedisTransactionOp::Store(entry) | RedisTransactionOp::Update(entry) => {
                    let key = format!("secreton:entry:{}", entry.id);
                    let value = serde_json::to_string(&entry).map_err(|e| {
                        StorageError::SerializationError {
                            message: e.to_string(),
                        }
                    })?;

                    if let Some(expires_at) = entry.expires_at {
                        let ttl = (expires_at - Utc::now()).num_seconds();
                        if ttl > 0 {
                            pipe.set_ex(&key, value, u64::try_from(ttl).unwrap_or(0));
                        } else {
                            // Already expired, ensure it is removed
                            pipe.del(&key);
                        }
                    } else {
                        pipe.set(&key, value);
                    }
                }
                RedisTransactionOp::Delete(id) => {
                    let key = format!("secreton:entry:{}", id);
                    pipe.del(&key);
                }
            }
        }

        pipe.query_async::<()>(&mut *conn)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to execute transaction pipeline: {}", e),
            })?;

        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}

impl RedisBackend {
    /// Create a new modern Redis backend with connection pooling
    pub async fn new(connection_url: &str) -> StorageResult<Self> {
        let client = Client::open(connection_url).map_err(|e| StorageError::ConnectionFailed {
            message: format!("Invalid Redis URL: {}", e),
        })?;

        let manager =
            ConnectionManager::new(client)
                .await
                .map_err(|e| StorageError::ConnectionFailed {
                    message: format!("Failed to create Redis connection manager: {}", e),
                })?;

        Ok(Self {
            manager: Arc::new(Mutex::new(manager)),
        })
    }
}

// `redis::aio::ConnectionManager` is not `Debug`, so these are written by hand rather
// than derived. They deliberately print no connection details.
impl std::fmt::Debug for RedisBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedisBackend")
    }
}

impl std::fmt::Debug for RedisTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisTransaction")
            .field("pending_operations", &self.operations.len())
            .finish()
    }
}

#[async_trait]
impl StorageBackend for RedisBackend {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let key = format!("secreton:entry:{}", entry.id);
        let value = serde_json::to_string(entry).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;

        let mut conn = self.manager.lock().await;

        if let Some(expires_at) = entry.expires_at {
            let ttl = (expires_at - Utc::now()).num_seconds();
            if ttl > 0 {
                conn.set_ex::<_, _, ()>(&key, value, u64::try_from(ttl).unwrap_or(0))
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to store entry with TTL: {}", e),
                    })?;
            } else {
                // Already expired, ensure it is removed
                conn.del::<_, ()>(&key)
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to delete expired entry: {}", e),
                    })?;
            }
        } else {
            conn.set::<_, _, ()>(&key, value)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to store entry: {}", e),
                })?;
        }

        // Also store path mapping
        if !entry.path.is_empty() {
            let path_key = format!("secreton:path:{}", entry.path);

            if let Some(expires_at) = entry.expires_at {
                let ttl = (expires_at - Utc::now()).num_seconds();
                if ttl > 0 {
                    conn.set_ex::<_, _, ()>(
                        &path_key,
                        entry.id.to_string(),
                        u64::try_from(ttl).unwrap_or(0),
                    )
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to store path mapping with TTL: {}", e),
                    })?;
                } else {
                    conn.del::<_, ()>(&path_key)
                        .await
                        .map_err(|e| StorageError::QueryFailed {
                            message: format!("Failed to delete expired path mapping: {}", e),
                        })?;
                }
            } else {
                conn.set::<_, _, ()>(&path_key, entry.id.to_string())
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to store path mapping: {}", e),
                    })?;
            }
        }

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let key = format!("secreton:entry:{}", id);
        let mut conn = self.manager.lock().await;

        let value: Option<String> =
            conn.get(&key)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to get entry: {}", e),
                })?;

        match value {
            Some(json_str) => {
                let entry = serde_json::from_str(&json_str).map_err(|e| {
                    StorageError::SerializationError {
                        message: e.to_string(),
                    }
                })?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let key = format!("secreton:path:{}", path);

        // Resolve the id and release the connection before reading the entry: `get_by_id`
        // takes the same non-reentrant lock, so holding it across that call deadlocks.
        let entry_id: Option<String> = {
            let mut conn = self.manager.lock().await;
            conn.get(&key)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to get path mapping: {}", e),
                })?
        };

        match entry_id {
            Some(id_str) => {
                let id =
                    Uuid::parse_str(&id_str).map_err(|e| StorageError::SerializationError {
                        message: e.to_string(),
                    })?;
                self.get_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        // For updates, we use the same store logic
        self.store(entry).await
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let entry_key = format!("secreton:entry:{}", id);
        let mut conn = self.manager.lock().await;

        // One server-side script removes the entry and the path mapping that points at it,
        // and it removes the mapping only while the mapping still resolves to this id.
        //
        // The previous implementation read the entry, deleted the entry key, and then
        // unconditionally deleted `secreton:path:<entry.path>`. If the path had been
        // rewritten between the read and the delete — a concurrent `store` or
        // `compare_and_set` publishing a replacement — that second delete removed the
        // *replacement's* mapping. The replacement's entry key survived, but nothing could
        // reach it by path any more, so it was lost while `get_by_path` reported a missing
        // record. Comparing the mapping's current value against the id being deleted is what
        // keeps a replacement reachable.
        let script = redis::Script::new(
            r"
            local mapping = redis.call('GET', KEYS[1])
            local removed = redis.call('DEL', KEYS[2])
            if removed > 0 and mapping == ARGV[1] then
                redis.call('DEL', KEYS[1])
            end
            return removed
            ",
        );

        // The path key is derived from the entry itself, which is what the mapping names,
        // so it can be computed here without a read. A record whose path is empty has no
        // mapping.
        let path_key = {
            let stored: Option<String> =
                conn.get(&entry_key)
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to read entry before delete: {}", e),
                    })?;
            match stored.as_deref().and_then(|json| {
                serde_json::from_str::<SecretEntry>(json)
                    .ok()
                    .map(|entry| entry.path)
            }) {
                Some(path) if !path.is_empty() => format!("secreton:path:{}", path),
                _ => String::new(),
            }
        };

        let removed: i64 = if path_key.is_empty() {
            // No mapping to consider; delete the entry alone.
            let removed: u64 =
                conn.del(&entry_key)
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to delete entry: {}", e),
                    })?;
            removed as i64
        } else {
            script
                .key(&path_key)
                .key(&entry_key)
                .arg(id.to_string())
                .invoke_async(&mut *conn)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete entry: {}", e),
                })?
        };

        Ok(removed > 0)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        // Resolve the path to an id under the connection lock, then delete by id, so the
        // path mapping and the entry are removed together and this reports whether a
        // record was actually there.
        match self.get_by_path(path).await? {
            Some(entry) => self.delete_by_id(entry.id).await,
            None => Ok(false),
        }
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let key = format!("secreton:path:{}", path);
        let mut conn = self.manager.lock().await;
        let exists: bool = conn
            .exists(&key)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to check existence: {}", e),
            })?;
        Ok(exists)
    }

    fn coordination(&self) -> Coordination {
        // Redis is the shared backend in the deployments this repository actually runs, so
        // its conditional operations are `SET ... NX` and `DEL` guarded by a Lua script:
        // each is a single server-side operation that every replica observes.
        Coordination::CrossProcess
    }

    /// Conditional write as a single server-side operation.
    ///
    /// Every precondition is evaluated against the *path* mapping, because the path is the
    /// identity the caller is fencing on. Checking an entry key derived from the caller's
    /// own id would find nothing for a fresh id and report success unconditionally — which
    /// is how an insert-if-absent turns into a lock that does not lock.
    ///
    /// The record body is never re-encoded inside the script: Lua's `cjson` renders an
    /// empty table as `{}`, so a round-trip turns an empty `tags` array into a map and the
    /// entry stops deserialising. The caller hands over a fully-formed value and the script
    /// only chooses to write it or not; id and creation time are preserved in Rust, where
    /// serde handles the types, exactly as the memory and file backends do.
    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: crate::Expect<'_>,
    ) -> StorageResult<bool> {
        let path_key = format!("secreton:path:{}", entry.path);

        // Read the current record first (without holding the connection lock across the
        // read) so a replacement keeps the identity and creation time the path already had.
        let existing = self.get_by_path(&entry.path).await?;
        let to_write = match &existing {
            Some(old) => {
                let mut updated = entry.clone();
                updated.id = old.id;
                updated.created_at = old.created_at;
                updated
            }
            None => entry.clone(),
        };

        let value =
            serde_json::to_string(&to_write).map_err(|e| StorageError::SerializationError {
                message: e.to_string(),
            })?;

        let expected_owner = match expect {
            crate::Expect::Owner(token) => Some(token.to_string()),
            _ => None,
        };

        // KEYS[1]=path key; ARGV[1]=value, ARGV[2]=write id, ARGV[3]=mode
        // ("absent" | "any" | "owner"), ARGV[4]=owner token (owner mode only).
        let script = redis::Script::new(
            r"
            local mode = ARGV[3]
            local existing_id = redis.call('GET', KEYS[1])

            if mode == 'absent' then
                if existing_id then
                    return 0
                end
            elseif mode == 'owner' then
                if not existing_id then
                    return 0
                end
                local current = redis.call('GET', 'secreton:entry:' .. existing_id)
                if not current then
                    return 0
                end
                local ok, decoded = pcall(cjson.decode, current)
                if not ok or type(decoded) ~= 'table' or type(decoded.metadata) ~= 'table'
                    or decoded.metadata['storage_owner'] ~= ARGV[4] then
                    return 0
                end
            end

            -- The value and the path mapping must name the same id, so the mapping never
            -- resolves to a record whose own id disagrees. A key left by the id this
            -- replaces is removed so the rewrite does not leak it.
            if existing_id and existing_id ~= ARGV[2] then
                redis.call('DEL', 'secreton:entry:' .. existing_id)
            end
            redis.call('SET', 'secreton:entry:' .. ARGV[2], ARGV[1])
            redis.call('SET', KEYS[1], ARGV[2])
            return 1
            ",
        );

        let mode = match expect {
            crate::Expect::Absent => "absent",
            crate::Expect::Any => "any",
            crate::Expect::Owner(_) => "owner",
        };

        let written: i64 = {
            let mut conn = self.manager.lock().await;
            script
                .key(&path_key)
                .arg(&value)
                .arg(to_write.id.to_string())
                .arg(mode)
                .arg(expected_owner.unwrap_or_default())
                .invoke_async(&mut *conn)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to compare-and-set entry: {}", e),
                })?
        };

        Ok(written == 1)
    }

    async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
        let path_key = format!("secreton:path:{}", path);
        let mut conn = self.manager.lock().await;

        // KEYS[1]=path key; ARGV[1]=owner token. Resolves the id, verifies ownership, and
        // deletes both the entry and the mapping in one script.
        let script = redis::Script::new(
            r"
            local id = redis.call('GET', KEYS[1])
            if not id then
                return 0
            end
            local entry_key = 'secreton:entry:' .. id
            local current = redis.call('GET', entry_key)
            if not current then
                return 0
            end
            local ok, decoded = pcall(cjson.decode, current)
            if not ok or not decoded.metadata or decoded.metadata['storage_owner'] ~= ARGV[1] then
                return 0
            end
            redis.call('DEL', entry_key)
            redis.call('DEL', KEYS[1])
            return 1
            ",
        );

        let removed: i64 = script
            .key(&path_key)
            .arg(token)
            .invoke_async(&mut *conn)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to delete owned entry: {}", e),
            })?;

        Ok(removed == 1)
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(RedisTransaction::new(self.manager.clone())))
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        // Redis holds entries keyed by id with a separate path index. Scanning keys is
        // the only way to enumerate them, and `SCAN` is the non-blocking cursor the
        // server provides for exactly this; `KEYS` would stall the whole server.
        let mut conn = self.manager.lock().await;
        let mut cursor: u64 = 0;
        let mut entries = Vec::new();

        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("secreton:entry:*")
                .arg("COUNT")
                .arg(100)
                .query_async(&mut *conn)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to scan entries: {}", e),
                })?;

            for key in keys {
                let value: Option<String> =
                    conn.get(&key)
                        .await
                        .map_err(|e| StorageError::QueryFailed {
                            message: format!("Failed to read entry during scan: {}", e),
                        })?;
                if let Some(json_str) = value
                    && let Ok(entry) = serde_json::from_str::<SecretEntry>(&json_str)
                {
                    entries.push(entry);
                }
            }

            cursor = next;
            if cursor == 0 {
                break;
            }
        }

        Ok(params.apply_to(entries))
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        Ok(self.list(params).await?.len() as u64)
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        Ok(HealthStatus {
            is_healthy: true,
            response_time_ms: 1.0,
            connections_active: 1,
            connections_idle: 0,
            last_error: None,
            uptime_seconds: 0,
        })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        Ok(StorageStats {
            total_entries: 0,
            total_size_bytes: 0,
            average_entry_size: 0.0,
            entries_by_security_level: HashMap::new(),
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn delete_expired(&self, _path_prefix: Option<String>) -> StorageResult<u64> {
        // Redis handles expiration automatically via TTL
        Ok(0)
    }

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError {
            backend: "Redis".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError {
            backend: "Redis".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}
