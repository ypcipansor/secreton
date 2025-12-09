// Terraform Integration - State management and backend integration
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum TerraformError {
    #[error("Backend error: {0}")]
    BackendError(String),
    #[error("State error: {0}")]
    StateError(String),
    #[error("Lock error: {0}")]
    LockError(String),
    #[error("Workspace error: {0}")]
    WorkspaceError(String),
}

pub type Result<T> = std::result::Result<T, TerraformError>;

/// Backend type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackendType {
    Consul,
    S3,
    HTTP,
    Local,
}

/// Terraform configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformConfig {
    pub backend_type: BackendType,
    pub state_path: String,
    pub lock_enabled: bool,
    pub lock_timeout_seconds: i64,
}

/// Terraform resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformResource {
    pub resource_type: String,
    pub name: String,
    pub provider: String,
    pub mode: String, // managed, data
    pub instances: Vec<HashMap<String, serde_json::Value>>,
}

/// Terraform state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformState {
    pub version: u32,
    pub terraform_version: String,
    pub serial: u64,
    pub lineage: String,
    pub outputs: HashMap<String, serde_json::Value>,
    pub resources: Vec<TerraformResource>,
    pub updated_at: DateTime<Utc>,
}

/// State lock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateLock {
    pub lock_id: String,
    pub operation: String,
    pub who: String,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub path: String,
}

/// Workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub name: String,
    pub state: Option<TerraformState>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Terraform Integration
pub struct TerraformIntegration {
    config: Arc<RwLock<TerraformConfig>>,
    states: Arc<RwLock<HashMap<String, TerraformState>>>, // workspace -> state
    locks: Arc<RwLock<HashMap<String, StateLock>>>,       // path -> lock
    workspaces: Arc<RwLock<HashMap<String, Workspace>>>,
}

impl TerraformIntegration {
    pub fn new(config: TerraformConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            states: Arc::new(RwLock::new(HashMap::new())),
            locks: Arc::new(RwLock::new(HashMap::new())),
            workspaces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize backend
    pub async fn init_backend(&self) -> Result<()> {
        let config = self.config.read().await;

        // Mock backend initialization
        match config.backend_type {
            BackendType::Consul => {
                tracing::info!("Initializing Consul backend at {}", config.state_path);
            }
            BackendType::S3 => {
                tracing::info!("Initializing S3 backend at {}", config.state_path);
            }
            BackendType::HTTP => {
                tracing::info!("Initializing HTTP backend at {}", config.state_path);
            }
            BackendType::Local => {
                tracing::info!("Initializing local backend at {}", config.state_path);
            }
        }

        // Create default workspace
        self.create_workspace("default".to_string()).await?;

        Ok(())
    }

    /// Get state
    pub async fn get_state(&self, workspace: &str) -> Result<TerraformState> {
        let states = self.states.read().await;
        states
            .get(workspace)
            .cloned()
            .ok_or_else(|| TerraformError::StateError("State not found".to_string()))
    }

    /// Update state
    pub async fn update_state(&self, workspace: &str, state: TerraformState) -> Result<()> {
        let mut states = self.states.write().await;
        states.insert(workspace.to_string(), state);

        // Update workspace timestamp
        let mut workspaces = self.workspaces.write().await;
        if let Some(ws) = workspaces.get_mut(workspace) {
            ws.updated_at = Utc::now();
        }

        Ok(())
    }

    /// Lock state
    pub async fn lock_state(&self, path: &str, lock: StateLock) -> Result<String> {
        let config = self.config.read().await;

        if !config.lock_enabled {
            return Err(TerraformError::LockError(
                "State locking is disabled".to_string(),
            ));
        }

        let mut locks = self.locks.write().await;

        // Check if already locked
        if locks.contains_key(path) {
            return Err(TerraformError::LockError(
                "State is already locked".to_string(),
            ));
        }

        let lock_id = lock.lock_id.clone();
        locks.insert(path.to_string(), lock);

        Ok(lock_id)
    }

    /// Unlock state
    pub async fn unlock_state(&self, path: &str, lock_id: &str) -> Result<()> {
        let mut locks = self.locks.write().await;

        if let Some(lock) = locks.get(path) {
            if lock.lock_id != lock_id {
                return Err(TerraformError::LockError(
                    "Lock ID does not match".to_string(),
                ));
            }

            locks.remove(path);
            Ok(())
        } else {
            Err(TerraformError::LockError("No lock found".to_string()))
        }
    }

    /// Create workspace
    pub async fn create_workspace(&self, name: String) -> Result<()> {
        let mut workspaces = self.workspaces.write().await;

        if workspaces.contains_key(&name) {
            return Err(TerraformError::WorkspaceError(
                "Workspace already exists".to_string(),
            ));
        }

        let workspace = Workspace {
            name: name.clone(),
            state: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        workspaces.insert(name.clone(), workspace);

        // Initialize empty state
        let state = TerraformState {
            version: 4,
            terraform_version: "1.5.0".to_string(),
            serial: 0,
            lineage: uuid::Uuid::new_v4().to_string(),
            outputs: HashMap::new(),
            resources: Vec::new(),
            updated_at: Utc::now(),
        };

        drop(workspaces);
        self.update_state(&name, state).await?;

        Ok(())
    }

    /// Delete workspace
    pub async fn delete_workspace(&self, name: &str) -> Result<()> {
        if name == "default" {
            return Err(TerraformError::WorkspaceError(
                "Cannot delete default workspace".to_string(),
            ));
        }

        let mut workspaces = self.workspaces.write().await;
        workspaces
            .remove(name)
            .ok_or_else(|| TerraformError::WorkspaceError("Workspace not found".to_string()))?;

        let mut states = self.states.write().await;
        states.remove(name);

        Ok(())
    }

    /// List workspaces
    pub async fn list_workspaces(&self) -> Vec<String> {
        let workspaces = self.workspaces.read().await;
        workspaces.keys().cloned().collect()
    }

    /// Get workspace
    pub async fn get_workspace(&self, name: &str) -> Option<Workspace> {
        let workspaces = self.workspaces.read().await;
        workspaces.get(name).cloned()
    }

    /// Check lock status
    pub async fn is_locked(&self, path: &str) -> bool {
        let locks = self.locks.read().await;
        locks.contains_key(path)
    }

    /// Get lock info
    pub async fn get_lock_info(&self, path: &str) -> Option<StateLock> {
        let locks = self.locks.read().await;
        locks.get(path).cloned()
    }

    /// Increment state serial
    pub async fn increment_serial(&self, workspace: &str) -> Result<u64> {
        let mut states = self.states.write().await;
        let state = states
            .get_mut(workspace)
            .ok_or_else(|| TerraformError::StateError("State not found".to_string()))?;

        state.serial += 1;
        state.updated_at = Utc::now();

        Ok(state.serial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> TerraformConfig {
        TerraformConfig {
            backend_type: BackendType::Consul,
            state_path: "secreton/terraform/state".to_string(),
            lock_enabled: true,
            lock_timeout_seconds: 300,
        }
    }

    fn create_test_state() -> TerraformState {
        TerraformState {
            version: 4,
            terraform_version: "1.5.0".to_string(),
            serial: 1,
            lineage: uuid::Uuid::new_v4().to_string(),
            outputs: HashMap::new(),
            resources: vec![TerraformResource {
                resource_type: "aws_instance".to_string(),
                name: "example".to_string(),
                provider: "registry.terraform.io/hashicorp/aws".to_string(),
                mode: "managed".to_string(),
                instances: vec![],
            }],
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_init_backend() {
        let tf = TerraformIntegration::new(create_test_config());

        tf.init_backend().await.unwrap();

        let workspaces = tf.list_workspaces().await;
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0], "default");
    }

    #[tokio::test]
    async fn test_state_management() {
        let tf = TerraformIntegration::new(create_test_config());
        tf.init_backend().await.unwrap();

        let state = create_test_state();

        // Update state
        tf.update_state("default", state.clone()).await.unwrap();

        // Get state
        let retrieved = tf.get_state("default").await.unwrap();
        assert_eq!(retrieved.serial, 1);
        assert_eq!(retrieved.resources.len(), 1);
        assert_eq!(retrieved.resources[0].resource_type, "aws_instance");
    }

    #[tokio::test]
    async fn test_state_locking() {
        let tf = TerraformIntegration::new(create_test_config());
        tf.init_backend().await.unwrap();

        let lock = StateLock {
            lock_id: uuid::Uuid::new_v4().to_string(),
            operation: "apply".to_string(),
            who: "user@example.com".to_string(),
            version: "1.5.0".to_string(),
            created_at: Utc::now(),
            path: "secreton/terraform/state/default".to_string(),
        };

        let path = "secreton/terraform/state/default";

        // Lock state
        let lock_id = tf.lock_state(path, lock.clone()).await.unwrap();
        assert!(!lock_id.is_empty());

        // Check lock
        assert!(tf.is_locked(path).await);

        // Try to lock again (should fail)
        let result = tf.lock_state(path, lock.clone()).await;
        assert!(result.is_err());

        // Unlock state
        tf.unlock_state(path, &lock_id).await.unwrap();

        // Check unlocked
        assert!(!tf.is_locked(path).await);
    }

    #[tokio::test]
    async fn test_workspace_management() {
        let tf = TerraformIntegration::new(create_test_config());
        tf.init_backend().await.unwrap();

        // Create workspace
        tf.create_workspace("production".to_string()).await.unwrap();

        // List workspaces
        let workspaces = tf.list_workspaces().await;
        assert_eq!(workspaces.len(), 2);
        assert!(workspaces.contains(&"default".to_string()));
        assert!(workspaces.contains(&"production".to_string()));

        // Get workspace
        let ws = tf.get_workspace("production").await.unwrap();
        assert_eq!(ws.name, "production");

        // Delete workspace
        tf.delete_workspace("production").await.unwrap();

        let workspaces = tf.list_workspaces().await;
        assert_eq!(workspaces.len(), 1);
    }

    #[tokio::test]
    async fn test_serial_increment() {
        let tf = TerraformIntegration::new(create_test_config());
        tf.init_backend().await.unwrap();

        let state = create_test_state();
        tf.update_state("default", state).await.unwrap();

        // Increment serial
        let new_serial = tf.increment_serial("default").await.unwrap();
        assert_eq!(new_serial, 2);

        let state = tf.get_state("default").await.unwrap();
        assert_eq!(state.serial, 2);
    }

    #[tokio::test]
    async fn test_cannot_delete_default_workspace() {
        let tf = TerraformIntegration::new(create_test_config());
        tf.init_backend().await.unwrap();

        let result = tf.delete_workspace("default").await;
        assert!(result.is_err());
    }
}
