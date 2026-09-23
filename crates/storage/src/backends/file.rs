//! File-based storage backend implementation using JSON serialization for persistence and directory scanning for queries.
//! This backend stores each SecretEntry as a separate JSON file in the configured storage directory,
//! enabling simple file-based storage with full CRUD operations, querying, and statistics collection.

use crate::{
    Coordination, HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError,
    StorageResult, StorageStats, StorageTransaction,
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

        Ok(Self { storage_path: path })
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

    /// Write an entry through a temporary file and a rename, so a reader never observes a
    /// half-written record.
    ///
    /// A plain `fs::write` truncates the destination before writing; a crash or a
    /// concurrent scanner in that window sees an empty or partial file. `rename` within a
    /// directory is atomic, which is the property [`StorageBackend::compare_and_set`]
    /// needs to be a real compare-and-set rather than a compare-and-maybe-write.
    fn write_entry_atomically(&self, file_path: &Path, entry: &SecretEntry) -> StorageResult<()> {
        let content =
            serde_json::to_string_pretty(entry).map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize entry: {}", e),
            })?;

        let tmp = file_path.with_extension("json.tmp");
        fs::write(&tmp, content).map_err(|e| StorageError::BackendError {
            backend: "File".to_string(),
            message: format!("Failed to write entry file {}: {}", tmp.display(), e),
        })?;
        fs::rename(&tmp, file_path).map_err(|e| StorageError::BackendError {
            backend: "File".to_string(),
            message: format!(
                "Failed to publish entry file {}: {}",
                file_path.display(),
                e
            ),
        })
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
        self.write_entry_atomically(&file_path, entry)
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
        self.write_entry_atomically(&self.entry_path(to_write.id), &to_write)?;
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
