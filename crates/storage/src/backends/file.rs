//! File-based storage backend implementation using JSON serialization for persistence and directory scanning for queries.
//! This backend stores each SecretEntry as a separate JSON file in the configured storage directory,
//! enabling simple file-based storage with full CRUD operations, querying, and statistics collection.

use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use uuid::Uuid;

/// File-based storage backend using JSON serialization
pub struct FileBackend {
    storage_path: PathBuf,
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

    /// Generate file path for a vault entry by ID
    fn entry_path(&self, id: Uuid) -> PathBuf {
        self.storage_path.join(format!("{}.json", id))
    }

    /// Read and deserialize a vault entry from file
    fn read_entry(&self, file_path: &Path) -> StorageResult<SecretEntry> {
        let content = fs::read_to_string(file_path).map_err(|e| StorageError::BackendError {
            backend: "File".to_string(),
            message: format!("Failed to read entry file {}: {}", file_path.display(), e),
        })?;

        serde_json::from_str(&content).map_err(|e| StorageError::SerializationError {
            message: format!("Failed to deserialize entry: {}", e),
        })
    }

    /// Serialize and write a vault entry to file
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
                    && !entry.path.starts_with(prefix) {
                        return false;
                    }

                // Filter by security level
                if let Some(min_level) = params.security_level
                    && entry.security_level < min_level {
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
                    && entry.owner_id != owner_id {
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
        self.write_entry(&file_path, entry)
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
        // For path-based deletion, we need to find the entry first
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
}
