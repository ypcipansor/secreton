//! Business logic services for secret management

use crate::error::*;
use crate::model::*;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

/// Core trait for secret engines
#[async_trait]
pub trait SecretEngine: Send + Sync {
    /// Get the engine type
    fn engine_type(&self) -> EngineType;

    /// Initialize the engine with configuration
    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()>;

    /// Read a secret from the engine
    async fn read(&self, path: &str) -> SecretResult<Option<Secret>>;

    /// Write a secret to the engine
    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret>;

    /// Delete a secret from the engine
    async fn delete(&mut self, path: &str) -> SecretResult<()>;

    /// List secrets under a path
    async fn list(&self, path: &str) -> SecretResult<Vec<String>>;

    /// Check if the engine is enabled
    fn is_enabled(&self) -> bool;

    /// Enable the engine
    fn enable(&mut self);

    /// Disable the engine
    fn disable(&mut self);
}

/// Secret engine registry for managing multiple engines
pub struct EngineRegistry {
    engines: HashMap<String, Box<dyn SecretEngine>>,
}

impl EngineRegistry {
    pub fn new() -> Self {
        Self {
            engines: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: String, engine: Box<dyn SecretEngine>) {
        self.engines.insert(name, engine);
    }

    pub fn get(&self, name: &str) -> Option<&dyn SecretEngine> {
        self.engines.get(name).map(|e| e.as_ref())
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Box<dyn SecretEngine>> {
        self.engines.get_mut(name)
    }

    pub fn list(&self) -> Vec<String> {
        self.engines.keys().cloned().collect()
    }

    pub fn remove(&mut self, name: &str) -> Option<Box<dyn SecretEngine>> {
        self.engines.remove(name)
    }
}

impl Default for EngineRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Secret management service
pub struct SecretService {
    registry: EngineRegistry,
}

impl SecretService {
    pub fn new() -> Self {
        Self {
            registry: EngineRegistry::new(),
        }
    }

    pub fn registry(&self) -> &EngineRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut EngineRegistry {
        &mut self.registry
    }

    /// Read a secret from any registered engine
    pub async fn read_secret(&self, engine: &str, path: &str) -> SecretResult<Option<Secret>> {
        let engine = self
            .registry
            .get(engine)
            .ok_or_else(|| SecretError::EngineNotFound(engine.to_string()))?;

        engine.read(path).await
    }

    /// Write a secret to any registered engine
    pub async fn write_secret(
        &mut self,
        engine: &str,
        path: &str,
        data: HashMap<String, Value>,
    ) -> SecretResult<Secret> {
        let engine = self
            .registry
            .get_mut(engine)
            .ok_or_else(|| SecretError::EngineNotFound(engine.to_string()))?;

        engine.write(path, data).await
    }

    /// Delete a secret from any registered engine
    pub async fn delete_secret(&mut self, engine: &str, path: &str) -> SecretResult<()> {
        let engine = self
            .registry
            .get_mut(engine)
            .ok_or_else(|| SecretError::EngineNotFound(engine.to_string()))?;

        engine.delete(path).await
    }

    /// List secrets from any registered engine
    pub async fn list_secrets(&self, engine: &str, path: &str) -> SecretResult<Vec<String>> {
        let engine = self
            .registry
            .get(engine)
            .ok_or_else(|| SecretError::EngineNotFound(engine.to_string()))?;

        engine.list(path).await
    }
}

impl Default for SecretService {
    fn default() -> Self {
        Self::new()
    }
}
