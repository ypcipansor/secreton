//! Key storage and versioning

use super::*;
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory key store
#[derive(Debug, Default)]
pub struct KeyStore {
    keys: HashMap<Uuid, Key>,
    key_versions: HashMap<Uuid, Vec<Uuid>>,
}

impl KeyStore {
    /// Create a new empty key store
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            key_versions: HashMap::new(),
        }
    }
    
    /// Add a new key to the store
    pub fn add_key(&mut self, key: Key) -> Result<Key> {
        if self.keys.contains_key(&key.id) {
            return Err(KeyError::KeyExists(key.id.to_string()));
        }
        
        // If this is a new version of an existing key, add to versions
        if let Some(previous_id) = &key.metadata.previous_version {
            self.key_versions
                .entry(*previous_id)
                .or_default()
                .push(key.id);
        }
        
        self.keys.insert(key.id, key.clone());
        
        // Initialize versions entry if new key
        self.key_versions.entry(key.id).or_default();
        
        Ok(key)
    }
    
    /// Get a key by ID
    pub fn get_key(&self, key_id: &Uuid) -> Option<&Key> {
        self.keys.get(key_id)
    }
    
    /// Get all versions of a key
    pub fn get_key_versions(&self, key_id: &Uuid) -> Option<Vec<&Key>> {
        self.key_versions
            .get(key_id)
            .map(|versions| {
                let mut result = Vec::new();
                for id in versions {
                    if let Some(key) = self.keys.get(id) {
                        result.push(key);
                    }
                }
                result
            })
    }
    
    /// Rotate a key (create a new version)
    pub fn rotate_key(&mut self, key_id: &Uuid, new_key: Key) -> Result<Key> {
        if !self.keys.contains_key(key_id) {
            return Err(KeyError::KeyNotFound(key_id.to_string()));
        }
        
        // Set the previous version on the new key
        let mut new_key = new_key;
        new_key.metadata.previous_version = Some(*key_id);
        
        self.add_key(new_key)
    }
    
    /// Delete a key and all its versions
    pub fn delete_key(&mut self, key_id: &Uuid) -> Result<()> {
        if !self.keys.contains_key(key_id) {
            return Err(KeyError::KeyNotFound(key_id.to_string()));
        }
        
        // Remove all versions
        if let Some(versions) = self.key_versions.remove(key_id) {
            for version_id in versions {
                self.keys.remove(&version_id);
            }
        }
        
        // Remove the key itself
        self.keys.remove(key_id);
        
        Ok(())
    }
}

/// Thread-safe wrapper around KeyStore
pub type SharedKeyStore = Arc<RwLock<KeyStore>>;
