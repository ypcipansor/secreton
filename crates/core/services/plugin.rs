use std::collections::HashMap;
use std::any::Any;
use libloading::{Library, Symbol};

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

pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn VaultPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self { plugins: HashMap::new() }
    }
    pub fn register(&mut self, plugin: Box<dyn VaultPlugin>) {
        self.plugins.insert(plugin.name().to_string(), plugin);
    }
    pub fn get(&self, name: &str) -> Option<&Box<dyn VaultPlugin>> {
        self.plugins.get(name)
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
    pub fn load(&mut self, plugin: Box<dyn VaultPlugin>) {
        let name = plugin.name().to_string();
        plugin.init();
        self.plugins.insert(name, plugin);
    }

    pub unsafe fn load_dynamic_library(&mut self, path: &str) -> Result<(), String> {
        let lib = Library::new(path).map_err(|e| format!("load error: {}", e))?;
        // Konvensi: plugin expose fn plugin_entry() -> Box<dyn VaultPlugin>
        let func: Symbol<unsafe extern fn() -> Box<dyn VaultPlugin>> = lib.get(b"plugin_entry").map_err(|e| format!("symbol error: {}", e))?;
        let plugin = func();
        let name = plugin.name().to_string();
        plugin.init();
        self.plugins.insert(name, plugin);
        // Note: lib harus disimpan jika ingin unload, di sini drop langsung (plugin tetap hidup di registry)
        Ok(())
    }
} 