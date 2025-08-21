//! Policy-based access control system for Brankas Adhyaksa
//! 
//! This module implements a flexible policy system for controlling access to resources
//! based on user roles and attributes.

mod model;
mod engine;

pub use model::*;
pub use engine::*;

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Error type for policy-related operations
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy not found")]
    NotFound,
    
    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),
    
    #[error("Permission denied")]
    PermissionDenied,
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Result type for policy operations
pub type PolicyResult<T> = std::result::Result<T, PolicyError>;

/// Represents a subject (user or service) that can be granted permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub id: Uuid,
    pub roles: Vec<String>,
    pub attributes: HashMap<String, String>,
}

impl Subject {
    /// Create a new subject with the given ID
    pub fn new(id: Uuid) -> Self {
        Self {
            id,
            roles: Vec::new(),
            attributes: HashMap::new(),
        }
    }
    
    /// Add a role to the subject
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }
    
    /// Add an attribute to the subject
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

/// Represents a resource that can be accessed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: Uuid,
    pub r#type: String,
    pub attributes: HashMap<String, String>,
}

impl Resource {
    /// Create a new resource with the given ID and type
    pub fn new(id: Uuid, r#type: impl Into<String>) -> Self {
        Self {
            id,
            r#type: r#type.into(),
            attributes: HashMap::new(),
        }
    }
    
    /// Add an attribute to the resource
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

/// Action that can be performed on a resource
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Create,
    Read,
    Update,
    Delete,
    List,
    Use,
    Admin,
    Custom(&'static str),
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Create => write!(f, "create"),
            Action::Read => write!(f, "read"),
            Action::Update => write!(f, "update"),
            Action::Delete => write!(f, "delete"),
            Action::List => write!(f, "list"),
            Action::Use => write!(f, "use"),
            Action::Admin => write!(f, "admin"),
            Action::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Context for authorization decisions
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AuthorizationContext {
    pub environment: HashMap<String, String>,
    pub request: HashMap<String, String>,
}

impl AuthorizationContext {
    /// Create a new empty context
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Add an environment variable to the context
    pub fn with_environment(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }
    
    /// Add a request attribute to the context
    pub fn with_request_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.request.insert(key.into(), value.into());
        self
    }
}
