//! Vault backend for secret storage

use std::collections::HashMap;
use tokio::sync::RwLock;
use crate::model::*;
use crate::error::*;

/// In-memory vault backend for secret storage
pub struct VaultBackend {
    storage: RwLock<HashMap<String, Secret>>,
}

impl VaultBackend {
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(HashMap::new()),
        }
    }

    /// Store a secret
    pub async fn store_secret(&self, secret: Secret) -> SecretResult<()> {
        let mut storage = self.storage.write().await;
        storage.insert(secret.path.clone(), secret);
        Ok(())
    }

    /// Retrieve a secret
    pub async fn get_secret(&self, path: &str) -> SecretResult<Option<Secret>> {
        let storage = self.storage.read().await;
        Ok(storage.get(path).cloned())
    }

    /// Delete a secret
    pub async fn delete_secret(&self, path: &str) -> SecretResult<()> {
        let mut storage = self.storage.write().await;
        storage.remove(path);
        Ok(())
    }

    /// List secrets under a path
    pub async fn list_secrets(&self, path: &str) -> SecretResult<Vec<String>> {
        let storage = self.storage.read().await;
        let keys: Vec<String> = storage.keys()
            .filter(|key| key.starts_with(path))
            .cloned()
            .collect();
        Ok(keys)
    }

    /// Check if backend is healthy
    pub async fn health_check(&self) -> SecretResult<()> {
        // In-memory backend is always healthy
        Ok(())
    }
}

impl Default for VaultBackend {
    fn default() -> Self {
        Self::new()
    }
}