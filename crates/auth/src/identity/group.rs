//! Identity groups and group management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Group creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreationRequest {
    /// Group name
    pub name: String,
    /// Group type
    pub group_type: super::entity::GroupType,
    /// Initial member entity IDs
    pub member_entity_ids: Vec<Uuid>,
    /// Initial member group IDs
    pub member_group_ids: Vec<Uuid>,
    /// Associated policies
    pub policies: Vec<String>,
    /// Group metadata
    pub metadata: HashMap<String, String>,
    /// Parent group ID
    pub parent_group_id: Option<Uuid>,
}

/// Group update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUpdateRequest {
    /// Group ID to update
    pub id: Uuid,
    /// Updated name
    pub name: Option<String>,
    /// Updated member entity IDs
    pub member_entity_ids: Option<Vec<Uuid>>,
    /// Updated member group IDs
    pub member_group_ids: Option<Vec<Uuid>>,
    /// Updated policies
    pub policies: Option<Vec<String>>,
    /// Updated metadata
    pub metadata: Option<HashMap<String, String>>,
}

/// Group lookup request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupLookupRequest {
    /// Group ID or name
    pub identifier: GroupIdentifier,
}

/// Group identifier (ID or name)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupIdentifier {
    /// Group ID
    Id(Uuid),
    /// Group name
    Name(String),
}

/// Group membership request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembershipRequest {
    /// Group identifier
    pub group: GroupIdentifier,
    /// Entity ID to check/add/remove
    pub entity_id: Uuid,
}

/// Group deletion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDeletionRequest {
    /// Group identifier
    pub identifier: GroupIdentifier,
}
