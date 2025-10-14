// Secret Migration - Tools for migrating secrets between storage backends
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("Migration failed: {0}")]
    MigrationFailed(String),
    #[error("Source backend error: {0}")]
    SourceError(String),
    #[error("Destination backend error: {0}")]
    DestinationError(String),
    #[error("Migration not found: {0}")]
    NotFound(String),
    #[error("Migration already in progress: {0}")]
    InProgress(String),
}

pub type Result<T> = std::result::Result<T, MigrationError>;

/// Storage backend type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackendType {
    File,
    Consul,
    Etcd,
    S3,
    PostgreSQL,
    MySQL,
    Raft,
}

/// Storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub backend_type: BackendType,
    pub connection_string: String,
    pub options: HashMap<String, String>,
}

/// Migration status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MigrationStatus {
    Pending,
    InProgress,
    Completed,
    Failed { reason: String },
    Paused,
}

/// Migration plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub id: String,
    pub name: String,
    pub source: BackendConfig,
    pub destination: BackendConfig,
    pub path_filters: Vec<String>, // Paths to migrate, e.g., "secret/*"
    pub batch_size: usize,
    pub verify_after_migration: bool,
    pub created_at: DateTime<Utc>,
}

/// Migration progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationProgress {
    pub migration_id: String,
    pub status: MigrationStatus,
    pub total_items: u64,
    pub migrated_items: u64,
    pub failed_items: u64,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub current_batch: u64,
    pub errors: Vec<String>,
}

impl MigrationProgress {
    pub fn new(migration_id: String) -> Self {
        Self {
            migration_id,
            status: MigrationStatus::Pending,
            total_items: 0,
            migrated_items: 0,
            failed_items: 0,
            started_at: None,
            completed_at: None,
            current_batch: 0,
            errors: Vec::new(),
        }
    }

    pub fn progress_percentage(&self) -> f64 {
        if self.total_items == 0 {
            return 0.0;
        }
        (self.migrated_items as f64 / self.total_items as f64) * 100.0
    }
}

/// Secret entry for migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub path: String,
    pub data: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Migration service
pub struct SecretMigrationService {
    plans: Arc<RwLock<HashMap<String, MigrationPlan>>>,
    progress: Arc<RwLock<HashMap<String, MigrationProgress>>>,
    // Mock storage for testing
    source_storage: Arc<RwLock<HashMap<String, SecretEntry>>>,
    dest_storage: Arc<RwLock<HashMap<String, SecretEntry>>>,
}

impl SecretMigrationService {
    pub fn new() -> Self {
        Self {
            plans: Arc::new(RwLock::new(HashMap::new())),
            progress: Arc::new(RwLock::new(HashMap::new())),
            source_storage: Arc::new(RwLock::new(HashMap::new())),
            dest_storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a migration plan
    pub async fn create_plan(&self, plan: MigrationPlan) -> Result<()> {
        let mut plans = self.plans.write().await;
        plans.insert(plan.id.clone(), plan.clone());

        // Initialize progress
        drop(plans);
        let mut progress = self.progress.write().await;
        progress.insert(plan.id.clone(), MigrationProgress::new(plan.id));

        Ok(())
    }

    /// Get migration plan
    pub async fn get_plan(&self, migration_id: &str) -> Result<MigrationPlan> {
        let plans = self.plans.read().await;
        plans
            .get(migration_id)
            .cloned()
            .ok_or_else(|| MigrationError::NotFound(migration_id.to_string()))
    }

    /// Start migration
    pub async fn start_migration(&self, migration_id: &str) -> Result<()> {
        // Check if already in progress
        {
            let progress = self.progress.read().await;
            if let Some(p) = progress.get(migration_id) {
                if p.status == MigrationStatus::InProgress {
                    return Err(MigrationError::InProgress(migration_id.to_string()));
                }
            }
        }

        let plan = self.get_plan(migration_id).await?;

        // Update progress status
        let mut progress = self.progress.write().await;
        let prog = progress
            .get_mut(migration_id)
            .ok_or_else(|| MigrationError::NotFound(migration_id.to_string()))?;

        prog.status = MigrationStatus::InProgress;
        prog.started_at = Some(Utc::now());
        drop(progress);

        // Perform migration
        self.perform_migration(&plan).await?;

        // Update progress to completed
        let mut progress = self.progress.write().await;
        if let Some(prog) = progress.get_mut(migration_id) {
            prog.status = MigrationStatus::Completed;
            prog.completed_at = Some(Utc::now());
        }

        Ok(())
    }

    /// Perform the actual migration
    async fn perform_migration(&self, plan: &MigrationPlan) -> Result<()> {
        // Get all items from source
        let source = self.source_storage.read().await;
        let items: Vec<_> = source
            .iter()
            .filter(|(path, _)| self.matches_filters(path, &plan.path_filters))
            .map(|(_, entry)| entry.clone())
            .collect();
        drop(source);

        let total = items.len() as u64;

        // Update total items
        {
            let mut progress = self.progress.write().await;
            if let Some(prog) = progress.get_mut(&plan.id) {
                prog.total_items = total;
            }
        }

        // Migrate in batches
        for (i, batch) in items.chunks(plan.batch_size).enumerate() {
            {
                let mut progress = self.progress.write().await;
                if let Some(prog) = progress.get_mut(&plan.id) {
                    prog.current_batch = i as u64 + 1;
                }
            }

            for entry in batch {
                match self.migrate_entry(entry).await {
                    Ok(_) => {
                        let mut progress = self.progress.write().await;
                        if let Some(prog) = progress.get_mut(&plan.id) {
                            prog.migrated_items += 1;
                        }
                    }
                    Err(e) => {
                        let mut progress = self.progress.write().await;
                        if let Some(prog) = progress.get_mut(&plan.id) {
                            prog.failed_items += 1;
                            prog.errors
                                .push(format!("Failed to migrate {}: {}", entry.path, e));
                        }
                    }
                }
            }

            // Verify if requested
            if plan.verify_after_migration {
                self.verify_batch(batch).await?;
            }
        }

        Ok(())
    }

    /// Migrate a single entry
    async fn migrate_entry(&self, entry: &SecretEntry) -> Result<()> {
        let mut dest = self.dest_storage.write().await;
        dest.insert(entry.path.clone(), entry.clone());
        Ok(())
    }

    /// Verify migrated entries
    async fn verify_batch(&self, batch: &[SecretEntry]) -> Result<()> {
        let dest = self.dest_storage.read().await;

        for entry in batch {
            if !dest.contains_key(&entry.path) {
                return Err(MigrationError::MigrationFailed(format!(
                    "Verification failed: {} not found in destination",
                    entry.path
                )));
            }
        }

        Ok(())
    }

    /// Check if path matches filters
    fn matches_filters(&self, path: &str, filters: &[String]) -> bool {
        if filters.is_empty() {
            return true;
        }

        for filter in filters {
            if filter.ends_with("/*") {
                let prefix = &filter[..filter.len() - 2];
                if path.starts_with(prefix) {
                    return true;
                }
            } else if path == filter {
                return true;
            }
        }

        false
    }

    /// Get migration progress
    pub async fn get_progress(&self, migration_id: &str) -> Result<MigrationProgress> {
        let progress = self.progress.read().await;
        progress
            .get(migration_id)
            .cloned()
            .ok_or_else(|| MigrationError::NotFound(migration_id.to_string()))
    }

    /// Pause migration
    pub async fn pause_migration(&self, migration_id: &str) -> Result<()> {
        let mut progress = self.progress.write().await;
        let prog = progress
            .get_mut(migration_id)
            .ok_or_else(|| MigrationError::NotFound(migration_id.to_string()))?;

        if prog.status == MigrationStatus::InProgress {
            prog.status = MigrationStatus::Paused;
        }

        Ok(())
    }

    /// Resume migration
    pub async fn resume_migration(&self, migration_id: &str) -> Result<()> {
        let mut progress = self.progress.write().await;
        let prog = progress
            .get_mut(migration_id)
            .ok_or_else(|| MigrationError::NotFound(migration_id.to_string()))?;

        if prog.status == MigrationStatus::Paused {
            prog.status = MigrationStatus::InProgress;
        }

        Ok(())
    }

    /// List all migrations
    pub async fn list_migrations(&self) -> Vec<MigrationPlan> {
        let plans = self.plans.read().await;
        plans.values().cloned().collect()
    }

    /// Add test data to source storage
    #[cfg(test)]
    pub async fn add_source_data(&self, path: String, data: Vec<u8>) {
        let mut source = self.source_storage.write().await;
        source.insert(
            path.clone(),
            SecretEntry {
                path,
                data,
                metadata: HashMap::new(),
            },
        );
    }

    /// Check if data exists in destination
    #[cfg(test)]
    pub async fn has_destination_data(&self, path: &str) -> bool {
        let dest = self.dest_storage.read().await;
        dest.contains_key(path)
    }
}

impl Default for SecretMigrationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_migration_plan() {
        let service = SecretMigrationService::new();

        let plan = MigrationPlan {
            id: "mig-1".to_string(),
            name: "Test Migration".to_string(),
            source: BackendConfig {
                backend_type: BackendType::File,
                connection_string: "/old".to_string(),
                options: HashMap::new(),
            },
            destination: BackendConfig {
                backend_type: BackendType::Raft,
                connection_string: "raft://".to_string(),
                options: HashMap::new(),
            },
            path_filters: vec!["secret/*".to_string()],
            batch_size: 100,
            verify_after_migration: true,
            created_at: Utc::now(),
        };

        service.create_plan(plan).await.unwrap();

        let retrieved = service.get_plan("mig-1").await.unwrap();
        assert_eq!(retrieved.name, "Test Migration");
    }

    #[tokio::test]
    async fn test_migration_execution() {
        let service = SecretMigrationService::new();

        // Add source data
        service
            .add_source_data("secret/key1".to_string(), b"value1".to_vec())
            .await;
        service
            .add_source_data("secret/key2".to_string(), b"value2".to_vec())
            .await;

        let plan = MigrationPlan {
            id: "mig-1".to_string(),
            name: "Test".to_string(),
            source: BackendConfig {
                backend_type: BackendType::File,
                connection_string: "/old".to_string(),
                options: HashMap::new(),
            },
            destination: BackendConfig {
                backend_type: BackendType::Raft,
                connection_string: "raft://".to_string(),
                options: HashMap::new(),
            },
            path_filters: vec!["secret/*".to_string()],
            batch_size: 10,
            verify_after_migration: true,
            created_at: Utc::now(),
        };

        service.create_plan(plan).await.unwrap();
        service.start_migration("mig-1").await.unwrap();

        let progress = service.get_progress("mig-1").await.unwrap();
        assert_eq!(progress.status, MigrationStatus::Completed);
        assert_eq!(progress.migrated_items, 2);
        assert_eq!(progress.failed_items, 0);

        // Verify data in destination
        assert!(service.has_destination_data("secret/key1").await);
        assert!(service.has_destination_data("secret/key2").await);
    }

    #[tokio::test]
    async fn test_path_filtering() {
        let service = SecretMigrationService::new();

        service
            .add_source_data("secret/app1/key".to_string(), b"val1".to_vec())
            .await;
        service
            .add_source_data("other/key".to_string(), b"val2".to_vec())
            .await;

        let plan = MigrationPlan {
            id: "mig-1".to_string(),
            name: "Filtered".to_string(),
            source: BackendConfig {
                backend_type: BackendType::File,
                connection_string: "/old".to_string(),
                options: HashMap::new(),
            },
            destination: BackendConfig {
                backend_type: BackendType::Raft,
                connection_string: "raft://".to_string(),
                options: HashMap::new(),
            },
            path_filters: vec!["secret/*".to_string()],
            batch_size: 10,
            verify_after_migration: false,
            created_at: Utc::now(),
        };

        service.create_plan(plan).await.unwrap();
        service.start_migration("mig-1").await.unwrap();

        let progress = service.get_progress("mig-1").await.unwrap();
        assert_eq!(progress.migrated_items, 1); // Only secret/* migrated

        assert!(service.has_destination_data("secret/app1/key").await);
        assert!(!service.has_destination_data("other/key").await);
    }

    #[tokio::test]
    async fn test_migration_progress() {
        let service = SecretMigrationService::new();

        for i in 0..5 {
            service
                .add_source_data(format!("secret/key{}", i), format!("val{}", i).into_bytes())
                .await;
        }

        let plan = MigrationPlan {
            id: "mig-1".to_string(),
            name: "Progress Test".to_string(),
            source: BackendConfig {
                backend_type: BackendType::File,
                connection_string: "/old".to_string(),
                options: HashMap::new(),
            },
            destination: BackendConfig {
                backend_type: BackendType::Raft,
                connection_string: "raft://".to_string(),
                options: HashMap::new(),
            },
            path_filters: vec![],
            batch_size: 2,
            verify_after_migration: false,
            created_at: Utc::now(),
        };

        service.create_plan(plan).await.unwrap();
        service.start_migration("mig-1").await.unwrap();

        let progress = service.get_progress("mig-1").await.unwrap();
        assert_eq!(progress.total_items, 5);
        assert_eq!(progress.migrated_items, 5);
        assert_eq!(progress.progress_percentage(), 100.0);
    }

    #[tokio::test]
    async fn test_pause_resume() {
        let service = SecretMigrationService::new();

        let plan = MigrationPlan {
            id: "mig-1".to_string(),
            name: "Pausable".to_string(),
            source: BackendConfig {
                backend_type: BackendType::File,
                connection_string: "/old".to_string(),
                options: HashMap::new(),
            },
            destination: BackendConfig {
                backend_type: BackendType::Raft,
                connection_string: "raft://".to_string(),
                options: HashMap::new(),
            },
            path_filters: vec![],
            batch_size: 10,
            verify_after_migration: false,
            created_at: Utc::now(),
        };

        service.create_plan(plan).await.unwrap();

        // Manually set to InProgress
        {
            let mut progress = service.progress.write().await;
            if let Some(prog) = progress.get_mut("mig-1") {
                prog.status = MigrationStatus::InProgress;
            }
        }

        service.pause_migration("mig-1").await.unwrap();
        let progress = service.get_progress("mig-1").await.unwrap();
        assert_eq!(progress.status, MigrationStatus::Paused);

        service.resume_migration("mig-1").await.unwrap();
        let progress = service.get_progress("mig-1").await.unwrap();
        assert_eq!(progress.status, MigrationStatus::InProgress);
    }
}
