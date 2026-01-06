//! Identity service for managing entities, aliases, and groups

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::alias::*;
use super::entity::*;
use super::group::*;
use crate::model::*;
use crate::service::AuthMethodResult;
use secreton_errors::SecretonError;

/// Identity service trait
#[async_trait]
pub trait IdentityService: Send + Sync {
    /// Create a new entity
    async fn create_entity(
        &self,
        name: String,
        metadata: HashMap<String, String>,
    ) -> AuthMethodResult<Entity>;

    /// Read an entity by ID
    async fn read_entity(&self, id: Uuid) -> AuthMethodResult<Option<Entity>>;

    /// Update an entity
    async fn update_entity(
        &self,
        id: Uuid,
        name: Option<String>,
        metadata: Option<HashMap<String, String>>,
        disabled: Option<bool>,
    ) -> AuthMethodResult<Entity>;

    /// Delete an entity
    async fn delete_entity(&self, id: Uuid) -> AuthMethodResult<()>;

    /// List entities
    async fn list_entities(&self) -> AuthMethodResult<Vec<Entity>>;

    /// Create an entity alias
    async fn create_entity_alias(
        &self,
        request: AliasCreationRequest,
    ) -> AuthMethodResult<EntityAlias>;

    /// Read entity aliases for an entity
    async fn read_entity_aliases(&self, entity_id: Uuid) -> AuthMethodResult<Vec<EntityAlias>>;

    /// Delete an entity alias
    async fn delete_entity_alias(
        &self,
        name: String,
        mount_accessor: String,
    ) -> AuthMethodResult<()>;

    /// Create a group
    async fn create_group(&self, request: GroupCreationRequest) -> AuthMethodResult<Group>;

    /// Read a group
    async fn read_group(&self, identifier: GroupIdentifier) -> AuthMethodResult<Option<Group>>;

    /// Update a group
    async fn update_group(&self, request: GroupUpdateRequest) -> AuthMethodResult<Group>;

    /// Delete a group
    async fn delete_group(&self, identifier: GroupIdentifier) -> AuthMethodResult<()>;

    /// List groups
    async fn list_groups(&self) -> AuthMethodResult<Vec<Group>>;

    /// Add entity to group
    async fn add_entity_to_group(&self, request: GroupMembershipRequest) -> AuthMethodResult<()>;

    /// Remove entity from group
    async fn remove_entity_from_group(
        &self,
        request: GroupMembershipRequest,
    ) -> AuthMethodResult<()>;

    /// Get user info by username
    async fn get_user_info(&self, username: &str) -> AuthMethodResult<Option<UserInfo>>;
}

/// In-memory identity service implementation
pub struct InMemoryIdentityService {
    entities: RwLock<HashMap<Uuid, Entity>>,
    aliases: RwLock<HashMap<String, EntityAlias>>, // Key: mount_accessor:name
    groups: RwLock<HashMap<Uuid, Group>>,
    group_names: RwLock<HashMap<String, Uuid>>, // For name-based lookups
}

impl InMemoryIdentityService {
    pub fn new() -> Self {
        Self {
            entities: RwLock::new(HashMap::new()),
            aliases: RwLock::new(HashMap::new()),
            groups: RwLock::new(HashMap::new()),
            group_names: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryIdentityService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdentityService for InMemoryIdentityService {
    async fn create_entity(
        &self,
        name: String,
        metadata: HashMap<String, String>,
    ) -> AuthMethodResult<Entity> {
        let entity = Entity {
            id: Uuid::new_v4(),
            name,
            metadata,
            creation_time: Utc::now(),
            last_update_time: Utc::now(),
            disabled: false,
            policies: Vec::new(),
            namespace_id: None,
        };

        let mut entities = self.entities.write().await;
        entities.insert(entity.id, entity.clone());

        Ok(entity)
    }

    async fn read_entity(&self, id: Uuid) -> AuthMethodResult<Option<Entity>> {
        let entities = self.entities.read().await;
        Ok(entities.get(&id).cloned())
    }

    async fn update_entity(
        &self,
        id: Uuid,
        name: Option<String>,
        metadata: Option<HashMap<String, String>>,
        disabled: Option<bool>,
    ) -> AuthMethodResult<Entity> {
        let mut entities = self.entities.write().await;
        if let Some(entity) = entities.get_mut(&id) {
            if let Some(name) = name {
                entity.name = name;
            }
            if let Some(metadata) = metadata {
                entity.metadata = metadata;
            }
            if let Some(disabled) = disabled {
                entity.disabled = disabled;
            }
            entity.last_update_time = Utc::now();
            Ok(entity.clone())
        } else {
            Err(SecretonError::UserNotFound {
                username: id.to_string(),
            })
        }
    }

    async fn delete_entity(&self, id: Uuid) -> AuthMethodResult<()> {
        let mut entities = self.entities.write().await;
        entities.remove(&id);
        Ok(())
    }

    async fn list_entities(&self) -> AuthMethodResult<Vec<Entity>> {
        let entities = self.entities.read().await;
        Ok(entities.values().cloned().collect())
    }

    async fn create_entity_alias(
        &self,
        request: AliasCreationRequest,
    ) -> AuthMethodResult<EntityAlias> {
        let alias = EntityAlias {
            id: Uuid::new_v4(),
            entity_id: request.entity_id,
            name: request.name.clone(),
            mount_accessor: request.mount_accessor.clone(),
            metadata: request.metadata,
            creation_time: Utc::now(),
            last_update_time: Utc::now(),
        };

        let key = format!("{}:{}", request.mount_accessor, request.name);
        let mut aliases = self.aliases.write().await;
        aliases.insert(key, alias.clone());

        Ok(alias)
    }

    async fn read_entity_aliases(&self, entity_id: Uuid) -> AuthMethodResult<Vec<EntityAlias>> {
        let aliases = self.aliases.read().await;
        Ok(aliases
            .values()
            .filter(|alias| alias.entity_id == entity_id)
            .cloned()
            .collect())
    }

    async fn delete_entity_alias(
        &self,
        name: String,
        mount_accessor: String,
    ) -> AuthMethodResult<()> {
        let key = format!("{}:{}", mount_accessor, name);
        let mut aliases = self.aliases.write().await;
        aliases.remove(&key);
        Ok(())
    }

    async fn create_group(&self, request: GroupCreationRequest) -> AuthMethodResult<Group> {
        let group = Group {
            id: Uuid::new_v4(),
            name: request.name.clone(),
            group_type: request.group_type,
            member_entity_ids: request.member_entity_ids,
            member_group_ids: request.member_group_ids,
            policies: request.policies,
            metadata: request.metadata,
            creation_time: Utc::now(),
            last_update_time: Utc::now(),
            parent_group_id: request.parent_group_id,
            namespace_id: None,
        };

        let mut groups = self.groups.write().await;
        let mut group_names = self.group_names.write().await;

        groups.insert(group.id, group.clone());
        group_names.insert(request.name, group.id);

        Ok(group)
    }

    async fn read_group(&self, identifier: GroupIdentifier) -> AuthMethodResult<Option<Group>> {
        let groups = self.groups.read().await;
        let group_names = self.group_names.read().await;

        match identifier {
            GroupIdentifier::Id(id) => Ok(groups.get(&id).cloned()),
            GroupIdentifier::Name(name) => {
                if let Some(id) = group_names.get(&name) {
                    Ok(groups.get(id).cloned())
                } else {
                    Ok(None)
                }
            }
        }
    }

    async fn update_group(&self, request: GroupUpdateRequest) -> AuthMethodResult<Group> {
        let mut groups = self.groups.write().await;
        let mut group_names = self.group_names.write().await;

        if let Some(group) = groups.get_mut(&request.id) {
            if let Some(name) = &request.name {
                // Update name mapping
                group_names.remove(&group.name);
                group_names.insert(name.clone(), request.id);
                group.name = name.clone();
            }
            if let Some(member_entity_ids) = request.member_entity_ids {
                group.member_entity_ids = member_entity_ids;
            }
            if let Some(member_group_ids) = request.member_group_ids {
                group.member_group_ids = member_group_ids;
            }
            if let Some(policies) = request.policies {
                group.policies = policies;
            }
            if let Some(metadata) = request.metadata {
                group.metadata = metadata;
            }
            group.last_update_time = Utc::now();
            Ok(group.clone())
        } else {
            Err(SecretonError::RoleNotFound {
                role_id: format!("group {}", request.id),
            })
        }
    }

    async fn delete_group(&self, identifier: GroupIdentifier) -> AuthMethodResult<()> {
        let mut groups = self.groups.write().await;
        let mut group_names = self.group_names.write().await;

        let id = match identifier {
            GroupIdentifier::Id(id) => id,
            GroupIdentifier::Name(name) => {
                if let Some(id) = group_names.get(&name) {
                    *id
                } else {
                    return Err(SecretonError::RoleNotFound {
                        role_id: format!("group {}", name),
                    });
                }
            }
        };

        if let Some(group) = groups.remove(&id) {
            group_names.remove(&group.name);
        }

        Ok(())
    }

    async fn list_groups(&self) -> AuthMethodResult<Vec<Group>> {
        let groups = self.groups.read().await;
        Ok(groups.values().cloned().collect())
    }

    async fn add_entity_to_group(&self, request: GroupMembershipRequest) -> AuthMethodResult<()> {
        let mut groups = self.groups.write().await;

        let group_id = match request.group {
            GroupIdentifier::Id(id) => id,
            GroupIdentifier::Name(name) => {
                let group_names = self.group_names.read().await;
                if let Some(id) = group_names.get(&name) {
                    *id
                } else {
                    return Err(SecretonError::RoleNotFound {
                        role_id: format!("group {}", name),
                    });
                }
            }
        };

        if let Some(group) = groups.get_mut(&group_id) {
            if !group.member_entity_ids.contains(&request.entity_id) {
                group.member_entity_ids.push(request.entity_id);
                group.last_update_time = Utc::now();
            }
            Ok(())
        } else {
            Err(SecretonError::RoleNotFound {
                role_id: format!("group {}", group_id),
            })
        }
    }

    async fn remove_entity_from_group(
        &self,
        request: GroupMembershipRequest,
    ) -> AuthMethodResult<()> {
        let mut groups = self.groups.write().await;

        let group_id = match request.group {
            GroupIdentifier::Id(id) => id,
            GroupIdentifier::Name(name) => {
                let group_names = self.group_names.read().await;
                if let Some(id) = group_names.get(&name) {
                    *id
                } else {
                    return Err(SecretonError::RoleNotFound {
                        role_id: format!("group {}", name),
                    });
                }
            }
        };

        if let Some(group) = groups.get_mut(&group_id) {
            group
                .member_entity_ids
                .retain(|&id| id != request.entity_id);
            group.last_update_time = Utc::now();
            Ok(())
        } else {
            Err(SecretonError::RoleNotFound {
                role_id: format!("group {}", group_id),
            })
        }
    }

    async fn get_user_info(&self, _username: &str) -> AuthMethodResult<Option<UserInfo>> {
        // This is a simplified implementation
        // In a real system, this would look up user info from entities and aliases
        Ok(None)
    }
}
