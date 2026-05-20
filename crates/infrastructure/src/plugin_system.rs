//! Plugin System Architecture
//!
//! Provides plugin lifecycle management with hooks for secret operations,
//! sandboxing for isolation, and plugin registry with dependency resolution.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
    #[error("Plugin load failed: {0}")]
    LoadFailed(String),
    #[error("Hook execution failed: {0}")]
    HookFailed(String),
    #[error("Dependency not met: {0}")]
    DependencyNotMet(String),
    #[error("Invalid plugin: {0}")]
    InvalidPlugin(String),
}

pub type Result<T> = std::result::Result<T, PluginError>;

/// Plugin hook types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub enum HookType {
    PreRead,
    PostRead,
    PreWrite,
    PostWrite,
    PreDelete,
    PostDelete,
    PreRotate,
    PostRotate,
}

/// Plugin lifecycle state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginState {
    Loaded,
    Initialized,
    Running,
    Paused,
    Failed,
    Unloaded,
}

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plugin {
    pub plugin_id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub entry_point: String,
    pub hooks: Vec<HookType>,
    pub dependencies: Vec<PluginDependency>,
    pub state: PluginState,
    pub loaded_at: Option<DateTime<Utc>>,
    pub config: HashMap<String, String>,
}

/// Plugin dependency specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDependency {
    pub plugin_name: String,
    pub version_requirement: String,
    pub optional: bool,
}

/// Plugin execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    pub operation: String,
    pub secret_path: String,
    pub metadata: HashMap<String, String>,
    pub user_context: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Hook execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResult {
    pub hook_id: String,
    pub plugin_id: String,
    pub hook_type: HookType,
    pub success: bool,
    pub modified_data: Option<HashMap<String, String>>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
}

/// Plugin sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub max_memory_mb: usize,
    pub max_cpu_percent: u8,
    pub max_execution_time_ms: u64,
    pub allowed_network_access: bool,
    pub allowed_file_access: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 128,
            max_cpu_percent: 50,
            max_execution_time_ms: 5000,
            allowed_network_access: false,
            allowed_file_access: vec![],
        }
    }
}

/// Plugin registry entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRegistryEntry {
    pub plugin_id: String,
    pub name: String,
    pub version: String,
    pub published_at: DateTime<Utc>,
    pub download_count: usize,
    pub verified: bool,
}

/// Plugin execution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginStats {
    pub plugin_id: String,
    pub total_executions: usize,
    pub successful_executions: usize,
    pub failed_executions: usize,
    pub average_execution_time_ms: f64,
    pub last_execution: Option<DateTime<Utc>>,
}

/// Plugin system manager
pub struct PluginSystem {
    plugins: Arc<RwLock<HashMap<String, Plugin>>>,
    hooks: Arc<RwLock<HashMap<HookType, Vec<String>>>>, // hook_type -> plugin_ids
    registry: Arc<RwLock<HashMap<String, PluginRegistryEntry>>>,
    stats: Arc<RwLock<HashMap<String, PluginStats>>>,
    sandbox_config: Arc<RwLock<SandboxConfig>>,
}

impl PluginSystem {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            hooks: Arc::new(RwLock::new(HashMap::new())),
            registry: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(HashMap::new())),
            sandbox_config: Arc::new(RwLock::new(SandboxConfig::default())),
        }
    }

    /// Load a plugin
    pub async fn load_plugin(&self, plugin: Plugin) -> Result<String> {
        // Validate plugin
        if plugin.name.is_empty() {
            return Err(PluginError::InvalidPlugin(
                "Name cannot be empty".to_string(),
            ));
        }

        // Check dependencies
        for dep in &plugin.dependencies {
            if !dep.optional {
                let plugins = self.plugins.read().await;
                let dep_exists = plugins.values().any(|p| p.name == dep.plugin_name);
                if !dep_exists {
                    return Err(PluginError::DependencyNotMet(format!(
                        "Required plugin '{}' not found",
                        dep.plugin_name
                    )));
                }
            }
        }

        let plugin_id = Uuid::new_v4().to_string();
        let mut loaded_plugin = plugin;
        loaded_plugin.plugin_id = plugin_id.clone();
        loaded_plugin.state = PluginState::Loaded;
        loaded_plugin.loaded_at = Some(Utc::now());

        // Register hooks
        let mut hooks = self.hooks.write().await;
        for hook_type in &loaded_plugin.hooks {
            hooks
                .entry(hook_type.clone())
                .or_insert_with(Vec::new)
                .push(plugin_id.clone());
        }

        // Initialize stats
        let mut stats = self.stats.write().await;
        stats.insert(
            plugin_id.clone(),
            PluginStats {
                plugin_id: plugin_id.clone(),
                total_executions: 0,
                successful_executions: 0,
                failed_executions: 0,
                average_execution_time_ms: 0.0,
                last_execution: None,
            },
        );

        let mut plugins = self.plugins.write().await;
        plugins.insert(plugin_id.clone(), loaded_plugin);

        Ok(plugin_id)
    }

    /// Initialize a loaded plugin
    pub async fn initialize_plugin(&self, plugin_id: &str) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        let plugin = plugins
            .get_mut(plugin_id)
            .ok_or_else(|| PluginError::PluginNotFound(plugin_id.to_string()))?;

        if plugin.state != PluginState::Loaded {
            return Err(PluginError::InvalidPlugin(format!(
                "Plugin must be in Loaded state, current: {:?}",
                plugin.state
            )));
        }

        // Mock initialization
        plugin.state = PluginState::Running;
        Ok(())
    }

    /// Execute hooks for a specific type
    pub async fn execute_hook(
        &self,
        hook_type: HookType,
        context: PluginContext,
    ) -> Result<Vec<HookResult>> {
        let hooks = self.hooks.read().await;
        let plugin_ids = hooks.get(&hook_type).cloned().unwrap_or_default();

        let mut results = Vec::new();
        let start_time = Utc::now();

        for plugin_id in plugin_ids {
            let plugins = self.plugins.read().await;
            let plugin = plugins.get(&plugin_id);

            if let Some(plugin) = plugin {
                if plugin.state != PluginState::Running {
                    continue;
                }

                // Execute hook in sandbox
                let result = self
                    .execute_in_sandbox(plugin, &hook_type, &context)
                    .await?;

                results.push(result);
            }
        }

        let _execution_time = Utc::now()
            .signed_duration_since(start_time)
            .num_milliseconds() as u64;

        // Update stats
        for result in &results {
            let mut stats = self.stats.write().await;
            if let Some(plugin_stats) = stats.get_mut(&result.plugin_id) {
                plugin_stats.total_executions += 1;
                if result.success {
                    plugin_stats.successful_executions += 1;
                } else {
                    plugin_stats.failed_executions += 1;
                }
                plugin_stats.last_execution = Some(Utc::now());

                // Update average execution time
                let total_time = plugin_stats.average_execution_time_ms
                    * (plugin_stats.total_executions - 1) as f64;
                plugin_stats.average_execution_time_ms = (total_time
                    + result.execution_time_ms as f64)
                    / plugin_stats.total_executions as f64;
            }
        }

        Ok(results)
    }

    /// Execute plugin hook in sandbox
    async fn execute_in_sandbox(
        &self,
        plugin: &Plugin,
        hook_type: &HookType,
        _context: &PluginContext,
    ) -> Result<HookResult> {
        let start_time = Utc::now();
        let sandbox = self.sandbox_config.read().await;

        // Mock sandboxed execution
        // In real implementation, this would use process isolation
        let success = true; // Simulate successful execution
        let execution_time = Utc::now()
            .signed_duration_since(start_time)
            .num_milliseconds() as u64;

        // Check execution time limit
        if execution_time > sandbox.max_execution_time_ms {
            return Ok(HookResult {
                hook_id: Uuid::new_v4().to_string(),
                plugin_id: plugin.plugin_id.clone(),
                hook_type: hook_type.clone(),
                success: false,
                modified_data: None,
                error: Some("Execution timeout".to_string()),
                execution_time_ms: execution_time,
            });
        }

        Ok(HookResult {
            hook_id: Uuid::new_v4().to_string(),
            plugin_id: plugin.plugin_id.clone(),
            hook_type: hook_type.clone(),
            success,
            modified_data: None,
            error: None,
            execution_time_ms: execution_time,
        })
    }

    /// Unload a plugin
    pub async fn unload_plugin(&self, plugin_id: &str) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        let plugin = plugins
            .get_mut(plugin_id)
            .ok_or_else(|| PluginError::PluginNotFound(plugin_id.to_string()))?;

        // Remove from hooks
        let mut hooks = self.hooks.write().await;
        for hook_type in &plugin.hooks {
            if let Some(plugin_ids) = hooks.get_mut(hook_type) {
                plugin_ids.retain(|id| id != plugin_id);
            }
        }

        plugin.state = PluginState::Unloaded;
        Ok(())
    }

    /// Get plugin by ID
    pub async fn get_plugin(&self, plugin_id: &str) -> Result<Plugin> {
        let plugins = self.plugins.read().await;
        plugins
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| PluginError::PluginNotFound(plugin_id.to_string()))
    }

    /// List all plugins
    pub async fn list_plugins(&self) -> Vec<Plugin> {
        let plugins = self.plugins.read().await;
        plugins.values().cloned().collect()
    }

    /// Get plugin statistics
    pub async fn get_plugin_stats(&self, plugin_id: &str) -> Result<PluginStats> {
        let stats = self.stats.read().await;
        stats
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| PluginError::PluginNotFound(plugin_id.to_string()))
    }

    /// Register plugin in registry
    pub async fn register_plugin(&self, plugin: &Plugin) -> Result<PluginRegistryEntry> {
        let entry = PluginRegistryEntry {
            plugin_id: plugin.plugin_id.clone(),
            name: plugin.name.clone(),
            version: plugin.version.clone(),
            published_at: Utc::now(),
            download_count: 0,
            verified: false,
        };

        let mut registry = self.registry.write().await;
        registry.insert(entry.plugin_id.clone(), entry.clone());

        Ok(entry)
    }

    /// Search registry
    pub async fn search_registry(&self, query: &str) -> Vec<PluginRegistryEntry> {
        let registry = self.registry.read().await;
        registry
            .values()
            .filter(|entry| entry.name.contains(query) || entry.plugin_id.contains(query))
            .cloned()
            .collect()
    }

    /// Update sandbox configuration
    pub async fn update_sandbox_config(&self, config: SandboxConfig) {
        let mut sandbox = self.sandbox_config.write().await;
        *sandbox = config;
    }

    /// Get hooks for a plugin
    pub async fn get_plugin_hooks(&self, plugin_id: &str) -> Result<Vec<HookType>> {
        let plugin = self.get_plugin(plugin_id).await?;
        Ok(plugin.hooks)
    }
}

impl Default for PluginSystem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_plugin() {
        let system = PluginSystem::new();
        let plugin = Plugin {
            plugin_id: String::new(),
            name: "test-plugin".to_string(),
            version: "0.1.0".to_string(),
            author: "Test Author".to_string(),
            description: "Test plugin".to_string(),
            entry_point: "main".to_string(),
            hooks: vec![HookType::PreRead, HookType::PostWrite],
            dependencies: vec![],
            state: PluginState::Loaded,
            loaded_at: None,
            config: HashMap::new(),
        };

        let plugin_id = system.load_plugin(plugin).await.unwrap();
        assert!(!plugin_id.is_empty());
    }

    #[tokio::test]
    async fn test_initialize_plugin() {
        let system = PluginSystem::new();
        let plugin = Plugin {
            plugin_id: String::new(),
            name: "test-plugin".to_string(),
            version: "0.1.0".to_string(),
            author: "Test Author".to_string(),
            description: "Test plugin".to_string(),
            entry_point: "main".to_string(),
            hooks: vec![HookType::PreRead],
            dependencies: vec![],
            state: PluginState::Loaded,
            loaded_at: None,
            config: HashMap::new(),
        };

        let plugin_id = system.load_plugin(plugin).await.unwrap();
        system.initialize_plugin(&plugin_id).await.unwrap();

        let loaded = system.get_plugin(&plugin_id).await.unwrap();
        assert_eq!(loaded.state, PluginState::Running);
    }

    #[tokio::test]
    async fn test_execute_hook() {
        let system = PluginSystem::new();
        let plugin = Plugin {
            plugin_id: String::new(),
            name: "test-plugin".to_string(),
            version: "0.1.0".to_string(),
            author: "Test Author".to_string(),
            description: "Test plugin".to_string(),
            entry_point: "main".to_string(),
            hooks: vec![HookType::PreRead],
            dependencies: vec![],
            state: PluginState::Loaded,
            loaded_at: None,
            config: HashMap::new(),
        };

        let plugin_id = system.load_plugin(plugin).await.unwrap();
        system.initialize_plugin(&plugin_id).await.unwrap();

        let context = PluginContext {
            operation: "read".to_string(),
            secret_path: "/secret/test".to_string(),
            metadata: HashMap::new(),
            user_context: Some("user1".to_string()),
            timestamp: Utc::now(),
        };

        let results = system
            .execute_hook(HookType::PreRead, context)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[tokio::test]
    async fn test_plugin_dependencies() {
        let system = PluginSystem::new();

        // Load base plugin
        let base_plugin = Plugin {
            plugin_id: String::new(),
            name: "base-plugin".to_string(),
            version: "0.1.0".to_string(),
            author: "Test".to_string(),
            description: "Base".to_string(),
            entry_point: "main".to_string(),
            hooks: vec![],
            dependencies: vec![],
            state: PluginState::Loaded,
            loaded_at: None,
            config: HashMap::new(),
        };
        system.load_plugin(base_plugin).await.unwrap();

        // Load dependent plugin
        let dependent_plugin = Plugin {
            plugin_id: String::new(),
            name: "dependent-plugin".to_string(),
            version: "0.1.0".to_string(),
            author: "Test".to_string(),
            description: "Dependent".to_string(),
            entry_point: "main".to_string(),
            hooks: vec![],
            dependencies: vec![PluginDependency {
                plugin_name: "base-plugin".to_string(),
                version_requirement: "0.1.0".to_string(),
                optional: false,
            }],
            state: PluginState::Loaded,
            loaded_at: None,
            config: HashMap::new(),
        };

        let result = system.load_plugin(dependent_plugin).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_plugin_stats() {
        let system = PluginSystem::new();
        let plugin = Plugin {
            plugin_id: String::new(),
            name: "test-plugin".to_string(),
            version: "0.1.0".to_string(),
            author: "Test".to_string(),
            description: "Test".to_string(),
            entry_point: "main".to_string(),
            hooks: vec![HookType::PreRead],
            dependencies: vec![],
            state: PluginState::Loaded,
            loaded_at: None,
            config: HashMap::new(),
        };

        let plugin_id = system.load_plugin(plugin).await.unwrap();
        system.initialize_plugin(&plugin_id).await.unwrap();

        let context = PluginContext {
            operation: "read".to_string(),
            secret_path: "/secret/test".to_string(),
            metadata: HashMap::new(),
            user_context: None,
            timestamp: Utc::now(),
        };

        system
            .execute_hook(HookType::PreRead, context)
            .await
            .unwrap();

        let stats = system.get_plugin_stats(&plugin_id).await.unwrap();
        assert_eq!(stats.total_executions, 1);
        assert_eq!(stats.successful_executions, 1);
    }

    #[tokio::test]
    async fn test_unload_plugin() {
        let system = PluginSystem::new();
        let plugin = Plugin {
            plugin_id: String::new(),
            name: "test-plugin".to_string(),
            version: "0.1.0".to_string(),
            author: "Test".to_string(),
            description: "Test".to_string(),
            entry_point: "main".to_string(),
            hooks: vec![HookType::PreRead],
            dependencies: vec![],
            state: PluginState::Loaded,
            loaded_at: None,
            config: HashMap::new(),
        };

        let plugin_id = system.load_plugin(plugin).await.unwrap();
        system.unload_plugin(&plugin_id).await.unwrap();

        let unloaded = system.get_plugin(&plugin_id).await.unwrap();
        assert_eq!(unloaded.state, PluginState::Unloaded);
    }
}
