//! Plugin System Module
//!
//! Comprehensive plugin system for extending Secreton functionality
//! with external plugins, custom secret engines, and integration hooks.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Unique plugin identifier
    pub id: String,
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin description
    pub description: String,
    /// Plugin author
    pub author: String,
    /// Plugin license
    pub license: String,
    /// Supported plugin types
    pub types: Vec<PluginType>,
    /// Plugin capabilities
    pub capabilities: Vec<PluginCapability>,
    /// Plugin dependencies
    pub dependencies: Vec<String>,
    /// Plugin configuration schema
    pub config_schema: Option<serde_json::Value>,
}

/// Supported plugin types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginType {
    /// Secret engine plugin
    SecretEngine,
    /// Authentication plugin
    AuthMethod,
    /// Storage backend plugin
    StorageBackend,
    /// Audit plugin
    Audit,
    /// Monitoring plugin
    Monitoring,
    /// Integration plugin
    Integration,
}

/// Plugin capabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginCapability {
    /// Can create secrets
    CreateSecrets,
    /// Can read secrets
    ReadSecrets,
    /// Can update secrets
    UpdateSecrets,
    /// Can delete secrets
    DeleteSecrets,
    /// Can list secrets
    ListSecrets,
    /// Can authenticate users
    Authenticate,
    /// Can authorize operations
    Authorize,
    /// Can store data
    Store,
    /// Can retrieve data
    Retrieve,
    /// Can audit operations
    Audit,
    /// Can monitor metrics
    Monitor,
    /// Can send notifications
    Notify,
}

/// Plugin execution context
#[derive(Debug, Clone)]
pub struct PluginContext {
    /// Plugin ID
    pub plugin_id: String,
    /// Operation ID
    pub operation_id: String,
    /// User context
    pub user_id: Option<String>,
    /// Request metadata
    pub metadata: HashMap<String, String>,
    /// Plugin configuration
    pub config: serde_json::Value,
}

/// Plugin execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    /// Success status
    pub success: bool,
    /// Result data
    pub data: Option<serde_json::Value>,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution metadata
    pub metadata: HashMap<String, String>,
}

/// Plugin trait that all plugins must implement
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get plugin metadata
    fn metadata(&self) -> &PluginMetadata;

    /// Initialize the plugin with configuration
    async fn initialize(&mut self, config: serde_json::Value) -> Result<(), PluginError>;

    /// Execute a plugin operation
    async fn execute(&self, context: PluginContext, operation: String, params: serde_json::Value) -> Result<PluginResult, PluginError>;

    /// Cleanup plugin resources
    async fn cleanup(&self) -> Result<(), PluginError>;

    /// Health check for the plugin
    async fn health_check(&self) -> Result<bool, PluginError>;

    /// Get plugin statistics
    async fn get_stats(&self) -> Result<HashMap<String, serde_json::Value>, PluginError>;
}

/// Plugin manager for loading and managing plugins
pub struct PluginManager {
    plugins: RwLock<HashMap<String, Box<dyn Plugin>>>,
    plugin_dir: PathBuf,
    config: PluginManagerConfig,
}

/// Plugin manager configuration
#[derive(Debug, Clone)]
pub struct PluginManagerConfig {
    /// Plugin directory path
    pub plugin_dir: PathBuf,
    /// Enable plugin hot reloading
    pub hot_reload: bool,
    /// Plugin execution timeout (seconds)
    pub execution_timeout: u64,
    /// Maximum memory usage per plugin (MB)
    pub max_memory_per_plugin: usize,
    /// Enable plugin isolation
    pub enable_isolation: bool,
    /// Plugin registry URL
    pub registry_url: Option<String>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new(config: PluginManagerConfig) -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            plugin_dir: config.plugin_dir.clone(),
            config,
        }
    }

    /// Load all plugins from the plugin directory
    pub async fn load_plugins(&self) -> Result<usize, PluginError> {
        let mut loaded_count = 0;
        let plugin_dir = &self.config.plugin_dir;

        if !plugin_dir.exists() {
            std::fs::create_dir_all(plugin_dir)?;
        }

        // Scan for plugin files
        for entry in std::fs::read_dir(plugin_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("so") ||
               path.extension().and_then(|s| s.to_str()) == Some("dll") ||
               path.file_name().and_then(|s| s.to_str()).unwrap_or("").starts_with("plugin_") {
                match self.load_plugin_from_file(&path).await {
                    Ok(_) => loaded_count += 1,
                    Err(e) => eprintln!("Failed to load plugin {:?}: {}", path, e),
                }
            }
        }

        Ok(loaded_count)
    }

    /// Load a plugin from a file
    async fn load_plugin_from_file(&self, path: &Path) -> Result<(), PluginError> {
        // This is a simplified implementation
        // In a real system, this would use dynamic library loading
        // For now, we'll support loading plugins from source files

        let plugin_id = path.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| PluginError::InvalidPlugin("Invalid plugin filename".to_string()))?
            .to_string();

        // For demonstration, we'll create a simple plugin
        // In practice, this would load a compiled shared library
        let plugin = Box::new(SimplePlugin::new(plugin_id.clone()));

        self.plugins.write().await.insert(plugin_id, plugin);
        Ok(())
    }

    /// Register a plugin instance
    pub async fn register_plugin(&self, plugin: Box<dyn Plugin>) -> Result<(), PluginError> {
        let metadata = plugin.metadata();
        let plugin_id = metadata.id.clone();

        if self.plugins.read().await.contains_key(&plugin_id) {
            return Err(PluginError::PluginAlreadyExists(plugin_id));
        }

        self.plugins.write().await.insert(plugin_id, plugin);
        Ok(())
    }

    /// Get a plugin by ID
    pub async fn get_plugin(&self, plugin_id: &str) -> Option<Arc<dyn Plugin>> {
        self.plugins.read().await.get(plugin_id).map(|p| Arc::from(p.as_ref()))
    }

    /// Execute a plugin operation
    pub async fn execute_plugin(
        &self,
        plugin_id: &str,
        operation: String,
        context: PluginContext,
        params: serde_json::Value,
    ) -> Result<PluginResult, PluginError> {
        let plugin = self.get_plugin(plugin_id).await
            .ok_or_else(|| PluginError::PluginNotFound(plugin_id.to_string()))?;

        plugin.execute(context, operation, params).await
    }

    /// List all loaded plugins
    pub async fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.plugins.read().await
            .values()
            .map(|p| p.metadata().clone())
            .collect()
    }

    /// Unload a plugin
    pub async fn unload_plugin(&self, plugin_id: &str) -> Result<(), PluginError> {
        let mut plugins = self.plugins.write().await;
        let plugin = plugins.remove(plugin_id)
            .ok_or_else(|| PluginError::PluginNotFound(plugin_id.to_string()))?;

        plugin.cleanup().await?;
        Ok(())
    }
}

/// Plugin error types
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    #[error("Plugin already exists: {0}")]
    PluginAlreadyExists(String),

    #[error("Invalid plugin: {0}")]
    InvalidPlugin(String),

    #[error("Plugin execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Plugin initialization failed: {0}")]
    InitializationFailed(String),

    #[error("Plugin configuration error: {0}")]
    ConfigurationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Simple plugin implementation for demonstration
pub struct SimplePlugin {
    metadata: PluginMetadata,
}

impl SimplePlugin {
    pub fn new(id: String) -> Self {
        Self {
            metadata: PluginMetadata {
                id,
                name: "Simple Plugin".to_string(),
                version: "1.0.0".to_string(),
                description: "A simple demonstration plugin".to_string(),
                author: "Secreton Team".to_string(),
                license: "MIT".to_string(),
                types: vec![PluginType::Integration],
                capabilities: vec![PluginCapability::Notify],
                dependencies: vec![],
                config_schema: None,
            },
        }
    }
}

#[async_trait]
impl Plugin for SimplePlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, _config: serde_json::Value) -> Result<(), PluginError> {
        Ok(())
    }

    async fn execute(&self, _context: PluginContext, operation: String, _params: serde_json::Value) -> Result<PluginResult, PluginError> {
        Ok(PluginResult {
            success: true,
            data: Some(serde_json::json!({"operation": operation, "result": "executed"})),
            error: None,
            metadata: HashMap::new(),
        })
    }

    async fn cleanup(&self) -> Result<(), PluginError> {
        Ok(())
    }

    async fn health_check(&self) -> Result<bool, PluginError> {
        Ok(true)
    }

    async fn get_stats(&self) -> Result<HashMap<String, serde_json::Value>, PluginError> {
        Ok(HashMap::new())
    }
}

pub mod dyn_password;
pub mod sops_file;
pub mod kms; 