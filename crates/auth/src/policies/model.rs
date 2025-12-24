//! Policy data models and DTOs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Policy types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyType {
    /// Role-Based Access Control
    RBAC,
    /// Attribute-Based Access Control
    ABAC,
    /// Custom policy type
    Custom(String),
}

/// Policy effect (allow or deny)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// Access control policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique policy identifier
    pub id: Uuid,
    /// Policy name
    pub name: String,
    /// Policy type
    pub policy_type: PolicyType,
    /// Policy effect
    pub effect: PolicyEffect,
    /// Policy rules/conditions
    pub rules: Vec<PolicyRule>,
    /// Policy metadata
    pub metadata: HashMap<String, String>,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last update time
    pub updated_at: DateTime<Utc>,
    /// Whether the policy is enabled
    pub enabled: bool,
}

/// Policy rule/condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule identifier
    pub id: Uuid,
    /// Rule name
    pub name: String,
    /// Rule conditions
    pub conditions: Vec<PolicyCondition>,
    /// Actions allowed/denied by this rule
    pub actions: Vec<String>,
    /// Resources this rule applies to
    pub resources: Vec<String>,
}

/// Policy condition for ABAC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    /// Condition attribute (e.g., "user.role", "resource.type")
    pub attribute: String,
    /// Condition operator
    pub operator: ConditionOperator,
    /// Condition value(s)
    pub values: Vec<String>,
}

/// Condition operators
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    In,
    NotIn,
    GreaterThan,
    LessThan,
    Regex,
}

/// Role definition for RBAC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique role identifier
    pub id: Uuid,
    /// Role name
    pub name: String,
    /// Role description
    pub description: Option<String>,
    /// Parent role (for hierarchical roles)
    pub parent_role: Option<Uuid>,
    /// Policies attached to this role
    pub policies: Vec<Uuid>,
    /// Role metadata
    pub metadata: HashMap<String, String>,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last update time
    pub updated_at: DateTime<Utc>,
}

/// Policy evaluation context
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    /// Subject (user/entity) attributes
    pub subject: HashMap<String, String>,
    /// Resource attributes
    pub resource: HashMap<String, String>,
    /// Action being performed
    pub action: String,
    /// Environment attributes
    pub environment: HashMap<String, String>,
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// Whether access is allowed
    pub allowed: bool,
    /// Reason for the decision
    pub reason: String,
    /// Policies that were evaluated
    pub evaluated_policies: Vec<Uuid>,
    /// Roles that were considered
    pub evaluated_roles: Vec<Uuid>,
    /// Evaluation timestamp
    pub timestamp: DateTime<Utc>,
}
