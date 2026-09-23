//! File-based storage backend implementation using JSON serialization for persistence and directory scanning for queries.
//! This backend stores each SecretEntry as a separate JSON file in the configured storage directory,
//! enabling simple file-based storage with full CRUD operations, querying, and statistics collection.

use crate::{
    Coordination, HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError,
    StorageFence, StorageResult, StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use chrono::Utc;
use secreton_domain::OAuthState;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use uuid::Uuid;

/// File-based storage backend using JSON serialization
#[derive(Debug)]
pub struct FileBackend {
    storage_path: PathBuf,
    /// Test-only: a park point inside the conditional write, so a test can force a
    /// concurrent replacement into the read-to-write window.
    #[cfg(test)]
    pause: Option<std::sync::Arc<crate::test_support::WritePause>>,
}

/// RAII guard for the file backend's cross-process advisory lock; released on drop.
///
/// Holding it is what makes [`StorageBackend::compare_and_set`] and
/// [`StorageBackend::delete_owned`] indivisible between separate processes sharing one
/// storage directory: the OS lock (`flock` on Unix, `LockFileEx` on Windows) excludes
/// every other holder, not merely other tasks in this process.
#[derive(Debug)]
struct FileLock {
    file: std::fs::File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl FileBackend {
    /// Create a new file-based backend
    pub fn new(storage_path: &str) -> StorageResult<Self> {
        let path = PathBuf::from(storage_path);

        // Create directory if it doesn't exist
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|e| StorageError::ConfigurationError {
                message: format!(
                    "Failed to create storage directory {}: {}",
                    path.display(),
                    e
                ),
            })?;
        }

        // Verify directory is writable
        let test_file = path.join(".write_test");
        fs::write(&test_file, b"test").map_err(|e| StorageError::ConfigurationError {
            message: format!(
                "Storage directory {} is not writable: {}",
                path.display(),
                e
            ),
        })?;
        let _ = fs::remove_file(&test_file);

        Ok(Self {
            storage_path: path,
            #[cfg(test)]
            pause: None,
        })
    }

    /// Test-only: force this backend's conditional writes to park just before they publish,
    /// so a test can replace the path's record in the window between the read and the write.
    #[cfg(test)]
    pub(crate) fn arm_compare_and_set_pause(
        &mut self,
    ) -> std::sync::Arc<crate::test_support::WritePause> {
        let pause = std::sync::Arc::new(crate::test_support::WritePause::new());
        self.pause = Some(pause.clone());
        pause
    }

    /// Test-only: the pause for the first attempt, taken once.
    #[cfg(test)]
    async fn take_pause(&self) {
        if let Some(pause) = &self.pause {
            pause.park().await;
        }
    }

    /// Generate file path for a secreton entry by ID
    fn entry_path(&self, id: Uuid) -> PathBuf {
        self.storage_path.join(format!("{}.json", id))
    }

    /// Read and deserialize a secreton entry from file
    fn read_entry(&self, file_path: &Path) -> StorageResult<SecretEntry> {
        let content = fs::read_to_string(file_path).map_err(|e| StorageError::BackendError {
            backend: "File".to_string(),
            message: format!("Failed to read entry file {}: {}", file_path.display(), e),
        })?;

        serde_json::from_str(&content).map_err(|e| StorageError::SerializationError {
            message: format!("Failed to deserialize entry: {}", e),
        })
    }

    /// Serialize and write a secreton entry to file
    fn write_entry(&self, file_path: &Path, entry: &SecretEntry) -> StorageResult<()> {
        let content =
            serde_json::to_string_pretty(entry).map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize entry: {}", e),
            })?;

        fs::write(file_path, content).map_err(|e| StorageError::BackendError {
            backend: "File".to_string(),
            message: format!("Failed to write entry file {}: {}", file_path.display(), e),
        })
    }

    /// Write an entry through a unique temporary file and a rename, so a reader never
    /// observes a half-written record and two concurrent writers never collide.
    ///
    /// A plain `fs::write` truncates the destination before writing; a crash or a
    /// concurrent scanner in that window sees an empty or partial file. `rename` within a
    /// directory is atomic, which is the property [`StorageBackend::compare_and_set`]
    /// needs to be a real compare-and-set rather than a compare-and-maybe-write.
    ///
    /// The temporary file is unique per call (`create_new`, so the kernel refuses a name
    /// that already exists) rather than derived only from the destination. `store` and
    /// `update` are not serialised by the advisory lock — a conditional write is, but a
    /// plain write is deliberately last-writer-wins — so two concurrent writes to the same
    /// id with a destination-derived temporary name would otherwise write the *same*
    /// temporary file and one would rename the other's bytes into place, or fail because
    /// the file had already been moved. A unique name makes each write's temporary file
    /// private to it, and the atomic rename publishes whichever finishes last. This is
    /// last-writer semantics, the same as the memory backend's plain `store`; it is not
    /// serialisation, which only `compare_and_set`/`store_fenced` (under the lock) claim.
    async fn write_entry_atomically(
        &self,
        file_path: &Path,
        entry: &SecretEntry,
    ) -> StorageResult<()> {
        let tmp = self.stage_entry(file_path, entry)?;

        // A test can park here — after its own temporary file exists, before the rename —
        // so a concurrent writer is forced into the window rather than hoped into it.
        #[cfg(test)]
        self.take_pause().await;

        self.publish_staged_entry(&tmp, file_path)
    }

    /// Serialize `entry` into a fresh, uniquely-named temporary file beside `file_path` and
    /// return its path. The temporary file is private to this call; a failure removes it.
    fn stage_entry(&self, file_path: &Path, entry: &SecretEntry) -> StorageResult<PathBuf> {
        let content =
            serde_json::to_string_pretty(entry).map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize entry: {}", e),
            })?;

        let mut tmp = self.temporary_path(file_path);
        let mut file = loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
            {
                Ok(file) => break file,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Overwhelmingly unlikely (a v4 UUID), but retry rather than reuse a
                    // name another writer owns.
                    tmp = self.temporary_path(file_path);
                }
                Err(e) => {
                    return Err(StorageError::BackendError {
                        backend: "File".to_string(),
                        message: format!(
                            "Failed to create temporary file {}: {}",
                            tmp.display(),
                            e
                        ),
                    });
                }
            }
        };

        if let Err(e) = std::io::Write::write_all(&mut file, content.as_bytes()) {
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(StorageError::BackendError {
                backend: "File".to_string(),
                message: format!("Failed to write temporary file {}: {}", tmp.display(), e),
            });
        }
        drop(file);
        Ok(tmp)
    }

    /// Atomically publish a staged temporary file over `file_path`. On failure the staged
    /// file is removed, so a failed write leaves no debris and — because the name is unique
    /// to the staging call — never removes another writer's temporary file.
    fn publish_staged_entry(&self, tmp: &Path, file_path: &Path) -> StorageResult<()> {
        if let Err(e) = fs::rename(tmp, file_path) {
            let _ = fs::remove_file(tmp);
            return Err(StorageError::BackendError {
                backend: "File".to_string(),
                message: format!(
                    "Failed to publish entry file {}: {}",
                    file_path.display(),
                    e
                ),
            });
        }
        Ok(())
    }

    /// A temporary path in the destination's directory, unique to this call.
    ///
    /// The `rename` must stay within one directory to be atomic, so the temporary file is a
    /// sibling of the destination. The name carries the destination's file name, a v4 UUID
    /// and this process's id, so it is unique across writers and processes; the extension is
    /// deliberately not `.json`, so a concurrent [`Self::scan_entries`] does not try to read
    /// a half-written temporary file as an entry.
    fn temporary_path(&self, file_path: &Path) -> PathBuf {
        let stem = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("entry");
        file_path.with_file_name(format!(
            ".{stem}.{}-{}.tmp",
            Uuid::new_v4(),
            std::process::id()
        ))
    }

    /// Path of the advisory lock that serialises this backend's conditional operations
    /// across processes sharing the same storage directory.
    fn lock_path(&self) -> PathBuf {
        self.storage_path.join(".secreton.lock")
    }

    /// Take the backend's exclusive advisory lock, waiting for it.
    ///
    /// The wait is a bounded non-blocking retry loop rather than a blocking `lock()`: the
    /// lock is held across the read and the write of a conditional operation, both of
    /// which are already synchronous `std::fs` calls in this backend, and blocking a
    /// Tokio worker for the whole wait would stall unrelated tasks. The lock is a real OS
    /// advisory lock (`flock` on Unix, `LockFileEx` on Windows), so it excludes other
    /// processes and other `FileBackend` instances in this process, not just tasks in it.
    fn acquire_lock(&self) -> StorageResult<FileLock> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_path())
            .map_err(|e| StorageError::BackendError {
                backend: "File".to_string(),
                message: format!("Failed to open storage lock file: {}", e),
            })?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(FileLock { file }),
                Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(StorageError::BackendError {
                        backend: "File".to_string(),
                        message: "Timed out waiting for the storage lock".to_string(),
                    });
                }
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(StorageError::BackendError {
                        backend: "File".to_string(),
                        message: format!("Failed to acquire storage lock: {}", e),
                    });
                }
            }
        }
    }

    /// Scan directory and collect all entries
    fn scan_entries(&self) -> StorageResult<Vec<SecretEntry>> {
        let mut entries = Vec::new();

        let read_dir =
            fs::read_dir(&self.storage_path).map_err(|e| StorageError::BackendError {
                backend: "File".to_string(),
                message: format!("Failed to read storage directory: {}", e),
            })?;

        for entry in read_dir {
            let entry = entry.map_err(|e| StorageError::BackendError {
                backend: "File".to_string(),
                message: format!("Failed to read directory entry: {}", e),
            })?;

            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                match self.read_entry(&path) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        // Log error but continue scanning
                        eprintln!("Failed to read entry {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Filter entries based on query parameters
    fn filter_entries(&self, entries: Vec<SecretEntry>, params: &QueryParams) -> Vec<SecretEntry> {
        entries
            .into_iter()
            .filter(|entry| {
                // Filter by path prefix
                if let Some(prefix) = &params.path_prefix
                    && !entry.path.starts_with(prefix)
                {
                    return false;
                }

                // Filter by security level
                if let Some(min_level) = params.security_level
                    && entry.security_level < min_level
                {
                    return false;
                }

                // Filter by tags
                if !params.tags.is_empty() {
                    let entry_tags: std::collections::HashSet<_> = entry.tags.iter().collect();
                    let filter_tags: std::collections::HashSet<_> = params.tags.iter().collect();
                    if !filter_tags.is_subset(&entry_tags) {
                        return false;
                    }
                }

                // Filter by owner
                if let Some(owner_id) = params.owner_id
                    && entry.owner_id != owner_id
                {
                    return false;
                }

                // Filter by metadata
                for (key, value) in &params.metadata_filters {
                    if let Some(entry_value) = entry.metadata.get(key) {
                        if entry_value != value {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                // Filter expired entries
                if !params.include_expired && entry.is_expired() {
                    return false;
                }

                true
            })
            .collect()
    }
}

#[async_trait]
impl StorageBackend for FileBackend {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let file_path = self.entry_path(entry.id);
        self.write_entry_atomically(&file_path, entry).await
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let file_path = self.entry_path(id);
        if file_path.exists() {
            match self.read_entry(&file_path) {
                Ok(entry) => Ok(Some(entry)),
                Err(_) => Ok(None), // File exists but corrupted
            }
        } else {
            Ok(None)
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        // For path-based lookup, we need to scan all entries
        let entries = self.scan_entries()?;
        for entry in entries {
            if entry.path == path {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        // For file backend, update is same as store (overwrite)
        let file_path = self.entry_path(entry.id);
        self.write_entry(&file_path, entry)
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let file_path = self.entry_path(id);
        if file_path.exists() {
            match fs::remove_file(&file_path) {
                Ok(_) => Ok(true),
                Err(e) => Err(StorageError::BackendError {
                    backend: "File".to_string(),
                    message: format!("Failed to delete entry file {}: {}", file_path.display(), e),
                }),
            }
        } else {
            Ok(false)
        }
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        // The read that locates the file and the unlink that removes it happen under the
        // backend's advisory lock, so a concurrent `compare_and_set` at the same path
        // cannot publish a new record between them and have this call delete it by id.
        let _guard = self.acquire_lock()?;
        let entries = self.scan_entries()?;
        for entry in entries {
            if entry.path == path {
                let file_path = self.entry_path(entry.id);
                return match fs::remove_file(&file_path) {
                    Ok(_) => Ok(true),
                    Err(e) => Err(StorageError::BackendError {
                        backend: "File".to_string(),
                        message: format!(
                            "Failed to delete entry file {}: {}",
                            file_path.display(),
                            e
                        ),
                    }),
                };
            }
        }
        Ok(false)
    }

    fn coordination(&self) -> Coordination {
        // Several processes may point at one storage directory; the OS advisory lock is
        // what arbitrates between them.
        Coordination::CrossProcess
    }

    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: crate::Expect<'_>,
    ) -> StorageResult<bool> {
        // The entire check-then-write runs while the advisory lock is held, so it is a
        // genuine compare-and-set for every other process sharing this directory.
        let _guard = self.acquire_lock()?;
        let existing = self.get_by_path(&entry.path).await?;

        let holds = match expect {
            crate::Expect::Absent => existing.is_none(),
            crate::Expect::Owner(token) => existing.as_ref().is_some_and(|e| e.has_owner(token)),
            crate::Expect::Any => true,
        };
        if !holds {
            return Ok(false);
        }

        let to_write = match &existing {
            Some(old) => {
                let mut updated = entry.clone();
                updated.id = old.id;
                updated.created_at = old.created_at;
                updated
            }
            None => entry.clone(),
        };
        self.write_entry_atomically(&self.entry_path(to_write.id), &to_write)
            .await?;
        Ok(true)
    }

    async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
        // Conditional on ownership *and* executed under the lock, so a record rewritten
        // by another attempt between a naive read and delete cannot be removed by this one.
        let _guard = self.acquire_lock()?;
        let Some(entry) = self.get_by_path(path).await? else {
            return Ok(false);
        };
        if !entry.has_owner(token) {
            return Ok(false);
        }
        match fs::remove_file(self.entry_path(entry.id)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::BackendError {
                backend: "File".to_string(),
                message: format!("Failed to delete owned entry: {}", e),
            }),
        }
    }

    /// The fence read and the write happen while the advisory lock is held, so the check
    /// and the publish cannot interleave with another process sharing this directory.
    async fn store_fenced(
        &self,
        entry: &SecretEntry,
        fence: StorageFence<'_>,
    ) -> StorageResult<bool> {
        let _guard = self.acquire_lock()?;

        let holds = self
            .get_by_path(fence.path)
            .await?
            .is_some_and(|held| held.has_owner(fence.token));
        if !holds {
            return Ok(false);
        }

        let existing = self.get_by_path(&entry.path).await?;
        let to_write = match existing {
            Some(old) => {
                let mut updated = entry.clone();
                updated.id = old.id;
                updated.created_at = old.created_at;
                updated
            }
            None => entry.clone(),
        };
        self.write_entry_atomically(&self.entry_path(to_write.id), &to_write)
            .await?;
        Ok(true)
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let entries = self.scan_entries()?;
        let mut filtered = self.filter_entries(entries, params);

        // Apply sorting if specified
        if let Some(sort_by) = &params.sort_by {
            match sort_by.as_str() {
                "path" => filtered.sort_by(|a, b| a.path.cmp(&b.path)),
                "created_at" => filtered.sort_by(|a, b| a.created_at.cmp(&b.created_at)),
                "updated_at" => filtered.sort_by(|a, b| a.updated_at.cmp(&b.updated_at)),
                _ => {} // No sorting
            }
        }

        // Apply sort order if specified
        if params.sort_order.as_deref() == Some("desc") {
            filtered.reverse();
        }

        // Apply offset and limit
        if let Some(offset) = params.offset {
            filtered = filtered.into_iter().skip(offset as usize).collect();
        }
        if let Some(limit) = params.limit {
            filtered.truncate(limit as usize);
        }

        Ok(filtered)
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let entries = self.scan_entries()?;
        let filtered = self.filter_entries(entries, params);
        Ok(filtered.len() as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let entries = self.scan_entries()?;
        Ok(entries.iter().any(|entry| entry.path == path))
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Err(StorageError::BackendError {
            backend: "File".to_string(),
            message: "Transactions not supported in File backend".to_string(),
        })
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start_time = SystemTime::now();

        // Check if directory is readable and writable
        let is_healthy = match fs::read_dir(&self.storage_path) {
            Ok(_) => {
                // Try to write a test file
                let test_file = self.storage_path.join(".health_check");
                fs::write(&test_file, b"health_check").is_ok()
                    && fs::remove_file(&test_file).is_ok()
            }
            Err(_) => false,
        };

        let response_time_ms = SystemTime::now()
            .duration_since(start_time)
            .unwrap_or_default()
            .as_millis() as f64;

        Ok(HealthStatus {
            is_healthy,
            response_time_ms,
            connections_active: 0, // File backend doesn't use connections
            connections_idle: 0,
            last_error: if is_healthy {
                None
            } else {
                Some("Directory not accessible".to_string())
            },
            uptime_seconds: 0, // Not tracked for file backend
        })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        let entries = self.scan_entries()?;
        let total_entries = entries.len() as u64;
        let total_size_bytes = entries.iter().map(|e| e.encrypted_data.len() as u64).sum();

        let mut entries_by_security_level = HashMap::new();
        let mut entries_created_today = 0;
        let mut entries_updated_today = 0;
        let mut expired_entries = 0;

        let today = Utc::now().date_naive();

        for entry in &entries {
            // Count by security level
            *entries_by_security_level
                .entry(entry.security_level)
                .or_insert(0) += 1;

            // Count entries created today
            if entry.created_at.date_naive() == today {
                entries_created_today += 1;
            }

            // Count entries updated today
            if entry.updated_at.date_naive() == today {
                entries_updated_today += 1;
            }

            // Count expired entries
            if entry.is_expired() {
                expired_entries += 1;
            }
        }

        Ok(StorageStats {
            total_entries,
            total_size_bytes,
            average_entry_size: if total_entries > 0 {
                total_size_bytes as f64 / total_entries as f64
            } else {
                0.0
            },
            entries_by_security_level,
            entries_created_today,
            entries_updated_today,
            expired_entries,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError {
            backend: "File".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError {
            backend: "File".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptionMetadata, SecurityLevel, StorageBackend};
    use std::sync::Arc;

    fn entry_at(id: Uuid, path: &str, payload: &[u8]) -> SecretEntry {
        let mut entry = SecretEntry::new(
            path.to_string(),
            payload.to_vec(),
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::nil(),
        );
        // The destination is chosen by id, so pin it; `SecretEntry::new`'s last argument is
        // the owner, not the id.
        entry.id = id;
        entry
    }

    /// Regression: the write staged into a temporary file named only after the destination
    /// (`<id>.json.tmp`), so two concurrent writes to the same destination used the *same*
    /// temporary path. One would rename the other's bytes into place, or the second rename
    /// would fail because the first had already moved the file away — either way a write
    /// either lost its own payload or failed.
    ///
    /// The interleaving is forced: the first write is parked after it has staged its
    /// temporary file and before the rename, the second write runs to completion in that
    /// window, and only then is the first released. Each write must publish its own payload
    /// with the atomic rename, and the second must not be able to observe or destroy the
    /// first's temporary file. The property is that a completed write's payload is readable
    /// and the destination always names one of the two written payloads, never a mixture.
    #[tokio::test]
    async fn concurrent_writes_to_one_destination_use_private_temporary_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let id = Uuid::new_v4();
        let path = "contract/one-destination";

        let mut first = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("backend");
        let pause = first.arm_compare_and_set_pause();
        let first = Arc::new(first);

        let first_entry = entry_at(id, path, b"first-payload");
        let first_write = {
            let backend = first.clone();
            let entry = first_entry.clone();
            tokio::spawn(async move { backend.store(&entry).await })
        };
        pause.wait_reached().await;

        // The second write completes entirely inside the first write's staging-to-rename
        // window, using the same destination id.
        let second = FileBackend::new(dir.path().to_str().expect("utf8 path")).expect("backend");
        let second_entry = entry_at(id, path, b"second-payload");
        second
            .store(&second_entry)
            .await
            .expect("the second concurrent write must succeed");

        // Releasing the first must not fail: its temporary file is its own, so the second
        // write could neither move nor remove it.
        pause.release();
        first_write
            .await
            .expect("task must not panic")
            .expect("the first concurrent write must succeed");

        // Exactly one record exists for the id, and it is one of the two payloads — not a
        // truncation, not a mixture, and not a failure caused by a shared temporary path.
        let resolved = first
            .get_by_id(id)
            .await
            .expect("read by id")
            .expect("the destination must exist");
        assert!(
            resolved.encrypted_data == b"first-payload"
                || resolved.encrypted_data == b"second-payload",
            "the destination must hold one writer's payload intact, got {:?}",
            String::from_utf8_lossy(&resolved.encrypted_data)
        );

        // No temporary file survives: each write either renamed its own or would have
        // removed it on failure, and neither could have leaked the other's.
        let leftovers = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "no temporary file may survive a completed write: {leftovers:?}"
        );
    }
}
