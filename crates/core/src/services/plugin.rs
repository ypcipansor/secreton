//! Enhanced Plugin System for Secreton
//!
//! Provides comprehensive plugin infrastructure for secrets engines, auth methods,
//! audit devices, and storage backends with lifecycle management.

use async_trait::async_trait;
use libloading::{Library, Symbol};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Error types for plugin system
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
    
    #[error("Plugin already loaded: {0}")]
    AlreadyLoaded(String),
    
    #[error("Plugin load failed: {0}")]
    LoadFailed(String),
    
    #[error("Plugin initialization failed: {0}")]
    InitFailed(String),
    
    #[error("Plugin operation failed: {0}")]
    OperationFailed(String),
    
    #[error("Invalid plugin configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Incompatible plugin version: {0}")]
    IncompatibleVersion(String),
}

/// Plugin type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginType {
    SecretsEngine,
    AuthMethod,
    AuditDevice,
    StorageBackend,
}

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub plugin_type: PluginType,
    pub description: String,
    pub author: String,
    pub required_version: String,
    pub capabilities: Vec<String>,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    pub mount_path: String,
    pub config: HashMap<String, serde_json::Value>,
    pub enabled: bool,
}

/// Plugin state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginState {
    Unloaded,
    Loading,
    Loaded,
    Initializing,
    Running,
    Stopping,
    Stopped,
    Failed,
}

/// Enhanced plugin trait
#[async_trait]
pub trait EnhancedPlugin: Send + Sync {
    fn metadata(&self) -> PluginMetadata;
    async fn initialize(&mut self, config: &PluginConfig) -> Result<(), PluginError>;
    async fn start(&mut self) -> Result<(), PluginError>;
    async fn stop(&mut self) -> Result<(), PluginError>;
    async fn health(&self) -> Result<bool, PluginError> { Ok(true) }
    async fn reload(&mut self, config: &PluginConfig) -> Result<(), PluginError> {
        self.stop().await?;
        self.initialize(config).await?;
        self.start().await
    }
}

/// Enhanced secrets engine plugin
#[async_trait]
pub trait EnhancedSecretsEngine: EnhancedPlugin {
    async fn read(&self, path: &str) -> Result<HashMap<String, serde_json::Value>, PluginError>;
    async fn write(&self, path: &str, data: HashMap<String, serde_json::Value>) -> Result<(), PluginError>;
    async fn delete(&self, path: &str) -> Result<(), PluginError>;
    async fn list(&self, path: &str) -> Result<Vec<String>, PluginError>;
}

/// Enhanced plugin registry
pub struct EnhancedPluginRegistry {
    plugins: Arc<RwLock<HashMap<String, PluginState>>>,
    secrets_engines: Arc<RwLock<HashMap<String, Arc<dyn EnhancedSecretsEngine>>>>,
}

impl EnhancedPluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            secrets_engines: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn register_secrets_engine(&self, name: String, engine: Arc<dyn EnhancedSecretsEngine>) -> Result<(), PluginError> {
        let mut engines = self.secrets_engines.write().await;
        engines.insert(name.clone(), engine);
        
        let mut plugins = self.plugins.write().await;
        plugins.insert(name, PluginState::Loaded);
        Ok(())
    }
    
    pub async fn get_secrets_engine(&self, name: &str) -> Result<Arc<dyn EnhancedSecretsEngine>, PluginError> {
        let engines = self.secrets_engines.read().await;
        engines.get(name).cloned()
            .ok_or_else(|| PluginError::PluginNotFound(name.to_string()))
    }
    
    pub async fn list_plugins(&self) -> Vec<String> {
        let plugins = self.plugins.read().await;
        plugins.keys().cloned().collect()
    }
    
    pub async fn update_state(&self, name: &str, state: PluginState) -> Result<(), PluginError> {
        let mut plugins = self.plugins.write().await;
        plugins.insert(name.to_string(), state);
        Ok(())
    }
}

impl Default for EnhancedPluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Legacy Plugin System (kept for compatibility) ==========

pub trait VaultPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn register(&self, registry: &mut PluginRegistry);
    fn init(&mut self) {}
    fn shutdown(&mut self) {}
    fn reload(&mut self) {}
    fn as_any(&self) -> &dyn Any;
}

pub trait SecretEnginePlugin: VaultPlugin {
    fn handle_secret(&self, action: &str, params: &serde_json::Value) -> serde_json::Value;
}

pub trait AuthPlugin: VaultPlugin {
    fn authenticate(&self, params: &serde_json::Value) -> bool;
}

pub trait AuditPlugin: VaultPlugin {
    fn audit(&self, event: &serde_json::Value);
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn VaultPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }
    pub fn register(&mut self, plugin: Box<dyn VaultPlugin>) {
        self.plugins.insert(plugin.name().to_string(), plugin);
    }
    pub fn get(&self, name: &str) -> Option<&dyn VaultPlugin> {
        self.plugins.get(name).map(|plugin| plugin.as_ref())
    }
    pub fn list(&self) -> Vec<String> {
        self.plugins.keys().cloned().collect()
    }
    pub fn unload(&mut self, name: &str) {
        if let Some(mut plugin) = self.plugins.remove(name) {
            plugin.shutdown();
        }
    }
    pub fn reload(&mut self, name: &str) {
        if let Some(plugin) = self.plugins.get_mut(name) {
            plugin.reload();
        }
    }
    pub fn load(&mut self, mut plugin: Box<dyn VaultPlugin>) {
        let name = plugin.name().to_string();
        plugin.init();
        self.plugins.insert(name, plugin);
    }

    /// Load a dynamic library plugin
    /// # Safety
    /// This function is unsafe because it loads dynamic libraries and calls foreign code.
    /// The caller must ensure that:
    /// - The path points to a valid dynamic library
    /// - The library exports a `plugin_entry` function with the correct signature
    /// - The loaded plugin is memory-safe and ABI-compatible
    pub unsafe fn load_dynamic_library(&mut self, path: &str) -> Result<(), String> {
        let lib = unsafe { Library::new(path) }.map_err(|e| format!("load error: {}", e))?;
        // Konvensi: plugin expose fn plugin_entry() -> Box<dyn VaultPlugin>
        let func: Symbol<unsafe extern "C" fn() -> Box<dyn VaultPlugin>> = unsafe { lib
            .get(b"plugin_entry") }
            .map_err(|e| format!("symbol error: {}", e))?;
        let mut plugin = unsafe { func() };
        let name = plugin.name().to_string();
        plugin.init();
        self.plugins.insert(name, plugin);
        // Note: lib harus disimpan jika ingin unload, di sini drop langsung (plugin tetap hidup di registry)
        Ok(())
    }
}
