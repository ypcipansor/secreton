use crate::services::plugin::{VaultPlugin, PluginRegistry};
use std::any::Any;

pub struct DynPasswordPlugin;

impl VaultPlugin for DynPasswordPlugin {
    fn name(&self) -> &'static str { "dyn_password" }
    fn version(&self) -> &'static str { "1.0.0" }
    fn register(&self, registry: &mut PluginRegistry) {
        registry.register(Box::new(Self));
    }
}

impl DynPasswordPlugin {
    pub fn generate(&self, length: usize) -> String {
        use rand::{distributions::Alphanumeric, Rng};
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }
}

impl DynPasswordPlugin {
    pub fn as_any(&self) -> &dyn Any {
        self
    }
} 