//! Identity entities and user management

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Identity entity representing a user or service account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    /// Unique identifier for the entity
    pub id: Uuid,
    /// Entity name
    pub name: String,
    /// Entity metadata
    pub metadata: HashMap<String, String>,
    /// Creation time
    pub creation_time: DateTime<Utc>,
    /// Last update time
    pub last_update_time: DateTime<Utc>,
    /// Whether the entity is disabled
    pub disabled: bool,
    /// Associated policies
    pub policies: Vec<String>,
    /// Namespace ID (for multi-tenancy)
    pub namespace_id: Option<String>,
}

/// Entity alias for linking entities to authentication methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityAlias {
    /// Unique identifier for the alias
    pub id: Uuid,
    /// Entity ID this alias belongs to
    pub entity_id: Uuid,
    /// Alias name
    pub name: String,
    /// Authentication method this alias is for
    pub mount_accessor: String,
    /// Metadata for the alias
    pub metadata: HashMap<String, String>,
    /// Creation time
    pub creation_time: DateTime<Utc>,
    /// Last update time
    pub last_update_time: DateTime<Utc>,
}

/// Identity group for organizing entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Unique identifier for the group
    pub id: Uuid,
    /// Group name
    pub name: String,
    /// Group type
    pub group_type: GroupType,
    /// Member entity IDs
    pub member_entity_ids: Vec<Uuid>,
    /// Member group IDs (for nested groups)
    pub member_group_ids: Vec<Uuid>,
    /// Associated policies
    pub policies: Vec<String>,
    /// Group metadata
    pub metadata: HashMap<String, String>,
    /// Creation time
    pub creation_time: DateTime<Utc>,
    /// Last update time
    pub last_update_time: DateTime<Utc>,
    /// Parent group ID (for hierarchical groups)
    pub parent_group_id: Option<Uuid>,
    /// Namespace ID
    pub namespace_id: Option<String>,
}

/// Types of identity groups
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupType {
    /// Internal group managed by Secret
    Internal,
    /// External group synced from external systems
    External,
}
