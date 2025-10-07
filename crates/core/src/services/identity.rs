//! Identity/Entity System
//!
//! Entity management with aliases and metadata for improved
//! access control and identity tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Error types for identity
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Entity not found: {0}")]
    EntityNotFound(String),
    
    #[error("Alias not found: {0}")]
    AliasNotFound(String),
    
    #[error("Alias already exists: {0}")]
    AliasExists(String),
    
    #[error("Cannot merge entity with itself")]
    SelfMerge,
    
    #[error("Invalid entity ID")]
    InvalidEntityId,
}

/// Entity represents a unique identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    /// Entity ID
    pub id: String,
    
    /// Entity name
    pub name: String,
    
    /// Metadata
    pub metadata: HashMap<String, String>,
    
    /// Policies attached
    pub policies: Vec<String>,
    
    /// Aliases
    pub aliases: Vec<String>,
    
    /// Merged from entity IDs
    pub merged_from: Vec<String>,
    
    /// Created at
    pub created_at: DateTime<Utc>,
    
    /// Updated at
    pub updated_at: DateTime<Utc>,
    
    /// Disabled
    pub disabled: bool,
}

impl Entity {
    /// Create new entity
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            metadata: HashMap::new(),
            policies: Vec::new(),
            aliases: Vec::new(),
            merged_from: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disabled: false,
        }
    }
    
    /// Add metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
        self.updated_at = Utc::now();
    }
    
    /// Add policy
    pub fn add_policy(&mut self, policy: String) {
        if !self.policies.contains(&policy) {
            self.policies.push(policy);
            self.updated_at = Utc::now();
        }
    }
    
    /// Remove policy
    pub fn remove_policy(&mut self, policy: &str) {
        self.policies.retain(|p| p != policy);
        self.updated_at = Utc::now();
    }
}

/// Alias represents an authentication source mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alias {
    /// Alias ID
    pub id: String,
    
    /// Entity ID this alias belongs to
    pub entity_id: String,
    
    /// Mount accessor (auth method)
    pub mount_accessor: String,
    
    /// Name in the auth method
    pub name: String,
    
    /// Metadata
    pub metadata: HashMap<String, String>,
    
    /// Created at
    pub created_at: DateTime<Utc>,
    
    /// Last used at
    pub last_used_at: Option<DateTime<Utc>>,
}

impl Alias {
    /// Create new alias
    pub fn new(entity_id: String, mount_accessor: String, name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            entity_id,
            mount_accessor,
            name,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_used_at: None,
        }
    }
}

/// Group represents a collection of entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Group ID
    pub id: String,
    
    /// Group name
    pub name: String,
    
    /// Member entity IDs
    pub member_entity_ids: HashSet<String>,
    
    /// Policies attached
    pub policies: Vec<String>,
    
    /// Metadata
    pub metadata: HashMap<String, String>,
    
    /// Created at
    pub created_at: DateTime<Utc>,
    
    /// Updated at
    pub updated_at: DateTime<Utc>,
}

impl Group {
    /// Create new group
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            member_entity_ids: HashSet::new(),
            policies: Vec::new(),
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
    
    /// Add member
    pub fn add_member(&mut self, entity_id: String) {
        self.member_entity_ids.insert(entity_id);
        self.updated_at = Utc::now();
    }
    
    /// Remove member
    pub fn remove_member(&mut self, entity_id: &str) {
        self.member_entity_ids.remove(entity_id);
        self.updated_at = Utc::now();
    }
}

/// Identity service
pub struct IdentityService {
    entities: Arc<RwLock<HashMap<String, Entity>>>,
    aliases: Arc<RwLock<HashMap<String, Alias>>>,
    groups: Arc<RwLock<HashMap<String, Group>>>,
    alias_index: Arc<RwLock<HashMap<String, String>>>, // (mount_accessor, name) -> alias_id
}

impl IdentityService {
    /// Create new identity service
    pub fn new() -> Self {
        Self {
            entities: Arc::new(RwLock::new(HashMap::new())),
            aliases: Arc::new(RwLock::new(HashMap::new())),
            groups: Arc::new(RwLock::new(HashMap::new())),
            alias_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Create entity
    pub async fn create_entity(&self, name: String) -> Entity {
        let entity = Entity::new(name);
        let mut entities = self.entities.write().await;
        entities.insert(entity.id.clone(), entity.clone());
        entity
    }
    
    /// Get entity
    pub async fn get_entity(&self, id: &str) -> Result<Entity, IdentityError> {
        let entities = self.entities.read().await;
        entities.get(id)
            .cloned()
            .ok_or_else(|| IdentityError::EntityNotFound(id.to_string()))
    }
    
    /// Update entity
    pub async fn update_entity(&self, id: &str, entity: Entity) -> Result<(), IdentityError> {
        let mut entities = self.entities.write().await;
        
        if !entities.contains_key(id) {
            return Err(IdentityError::EntityNotFound(id.to_string()));
        }
        
        entities.insert(id.to_string(), entity);
        Ok(())
    }
    
    /// Delete entity
    pub async fn delete_entity(&self, id: &str) -> Result<(), IdentityError> {
        let mut entities = self.entities.write().await;
        let mut aliases = self.aliases.write().await;
        let mut alias_index = self.alias_index.write().await;
        
        // Remove entity
        entities.remove(id)
            .ok_or_else(|| IdentityError::EntityNotFound(id.to_string()))?;
        
        // Remove associated aliases
        let alias_ids: Vec<String> = aliases.values()
            .filter(|a| a.entity_id == id)
            .map(|a| a.id.clone())
            .collect();
        
        for alias_id in alias_ids {
            if let Some(alias) = aliases.remove(&alias_id) {
                let key = format!("{}:{}", alias.mount_accessor, alias.name);
                alias_index.remove(&key);
            }
        }
        
        Ok(())
    }
    
    /// Create alias
    pub async fn create_alias(
        &self,
        entity_id: String,
        mount_accessor: String,
        name: String,
    ) -> Result<Alias, IdentityError> {
        let entities = self.entities.read().await;
        
        if !entities.contains_key(&entity_id) {
            return Err(IdentityError::EntityNotFound(entity_id));
        }
        drop(entities);
        
        let key = format!("{}:{}", mount_accessor, name);
        let mut alias_index = self.alias_index.write().await;
        
        if alias_index.contains_key(&key) {
            return Err(IdentityError::AliasExists(key));
        }
        
        let alias = Alias::new(entity_id.clone(), mount_accessor, name);
        alias_index.insert(key, alias.id.clone());
        drop(alias_index);
        
        let mut aliases = self.aliases.write().await;
        aliases.insert(alias.id.clone(), alias.clone());
        
        // Add alias to entity
        let mut entities = self.entities.write().await;
        if let Some(entity) = entities.get_mut(&entity_id) {
            entity.aliases.push(alias.id.clone());
        }
        
        Ok(alias)
    }
    
    /// Get alias
    pub async fn get_alias(&self, id: &str) -> Result<Alias, IdentityError> {
        let aliases = self.aliases.read().await;
        aliases.get(id)
            .cloned()
            .ok_or_else(|| IdentityError::AliasNotFound(id.to_string()))
    }
    
    /// Lookup entity by alias
    pub async fn lookup_entity_by_alias(
        &self,
        mount_accessor: &str,
        name: &str,
    ) -> Result<Entity, IdentityError> {
        let key = format!("{}:{}", mount_accessor, name);
        
        let alias_id = {
            let alias_index = self.alias_index.read().await;
            alias_index.get(&key)
                .ok_or_else(|| IdentityError::AliasNotFound(key.clone()))?
                .clone()
        };
        
        let entity_id = {
            let aliases = self.aliases.read().await;
            let alias = aliases.get(&alias_id)
                .ok_or_else(|| IdentityError::AliasNotFound(alias_id.clone()))?;
            alias.entity_id.clone()
        };
        
        self.get_entity(&entity_id).await
    }
    
    /// Merge entities
    pub async fn merge_entities(
        &self,
        from_id: &str,
        to_id: &str,
    ) -> Result<(), IdentityError> {
        if from_id == to_id {
            return Err(IdentityError::SelfMerge);
        }
        
        let mut entities = self.entities.write().await;
        
        let from_entity = entities.get(from_id)
            .ok_or_else(|| IdentityError::EntityNotFound(from_id.to_string()))?
            .clone();
        
        let to_entity = entities.get_mut(to_id)
            .ok_or_else(|| IdentityError::EntityNotFound(to_id.to_string()))?;
        
        // Merge policies
        for policy in from_entity.policies {
            if !to_entity.policies.contains(&policy) {
                to_entity.policies.push(policy);
            }
        }
        
        // Merge metadata
        to_entity.metadata.extend(from_entity.metadata);
        
        // Merge aliases
        to_entity.aliases.extend(from_entity.aliases.clone());
        
        // Track merge
        to_entity.merged_from.push(from_id.to_string());
        to_entity.updated_at = Utc::now();
        
        drop(entities);
        
        // Update aliases to point to new entity
        let mut aliases = self.aliases.write().await;
        for alias_id in from_entity.aliases {
            if let Some(alias) = aliases.get_mut(&alias_id) {
                alias.entity_id = to_id.to_string();
            }
        }
        
        // Remove old entity
        let mut entities = self.entities.write().await;
        entities.remove(from_id);
        
        Ok(())
    }
    
    /// Create group
    pub async fn create_group(&self, name: String) -> Group {
        let group = Group::new(name);
        let mut groups = self.groups.write().await;
        groups.insert(group.id.clone(), group.clone());
        group
    }
    
    /// Get group
    pub async fn get_group(&self, id: &str) -> Result<Group, IdentityError> {
        let groups = self.groups.read().await;
        groups.get(id)
            .cloned()
            .ok_or_else(|| IdentityError::EntityNotFound(id.to_string()))
    }
    
    /// List all entities
    pub async fn list_entities(&self) -> Vec<Entity> {
        let entities = self.entities.read().await;
        entities.values().cloned().collect()
    }
}

impl Default for IdentityService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_create_entity() {
        let service = IdentityService::new();
        
        let entity = service.create_entity("user1".to_string()).await;
        assert_eq!(entity.name, "user1");
        assert!(!entity.id.is_empty());
        
        let retrieved = service.get_entity(&entity.id).await.unwrap();
        assert_eq!(retrieved.name, "user1");
    }
    
    #[tokio::test]
    async fn test_create_alias() {
        let service = IdentityService::new();
        
        let entity = service.create_entity("user1".to_string()).await;
        
        let alias = service.create_alias(
            entity.id.clone(),
            "userpass".to_string(),
            "john".to_string(),
        ).await.unwrap();
        
        assert_eq!(alias.entity_id, entity.id);
        assert_eq!(alias.mount_accessor, "userpass");
        assert_eq!(alias.name, "john");
    }
    
    #[tokio::test]
    async fn test_lookup_by_alias() {
        let service = IdentityService::new();
        
        let entity = service.create_entity("user1".to_string()).await;
        
        service.create_alias(
            entity.id.clone(),
            "userpass".to_string(),
            "john".to_string(),
        ).await.unwrap();
        
        let found = service.lookup_entity_by_alias("userpass", "john").await.unwrap();
        assert_eq!(found.id, entity.id);
    }
    
    #[tokio::test]
    async fn test_merge_entities() {
        let service = IdentityService::new();
        
        let mut entity1 = service.create_entity("user1".to_string()).await;
        entity1.add_policy("policy1".to_string());
        service.update_entity(&entity1.id, entity1.clone()).await.unwrap();
        
        let mut entity2 = service.create_entity("user2".to_string()).await;
        entity2.add_policy("policy2".to_string());
        service.update_entity(&entity2.id, entity2.clone()).await.unwrap();
        
        service.merge_entities(&entity1.id, &entity2.id).await.unwrap();
        
        let merged = service.get_entity(&entity2.id).await.unwrap();
        assert!(merged.policies.contains(&"policy1".to_string()));
        assert!(merged.policies.contains(&"policy2".to_string()));
        
        assert!(service.get_entity(&entity1.id).await.is_err());
    }
    
    #[tokio::test]
    async fn test_create_group() {
        let service = IdentityService::new();
        
        let entity1 = service.create_entity("user1".to_string()).await;
        let entity2 = service.create_entity("user2".to_string()).await;
        
        let mut group = service.create_group("admins".to_string()).await;
        group.add_member(entity1.id.clone());
        group.add_member(entity2.id.clone());
        
        assert_eq!(group.member_entity_ids.len(), 2);
        assert!(group.member_entity_ids.contains(&entity1.id));
    }
}
