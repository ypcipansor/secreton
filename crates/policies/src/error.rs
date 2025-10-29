//! Policy domain errors

use std::fmt;
use thiserror::Error;

/// Policy domain error types
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy not found: {policy_id}")]
    PolicyNotFound { policy_id: String },

    #[error("Role not found: {role_id}")]
    RoleNotFound { role_id: String },

    #[error("Invalid policy syntax: {details}")]
    InvalidPolicySyntax { details: String },

    #[error("Policy evaluation failed: {reason}")]
    EvaluationFailed { reason: String },

    #[error("Policy already exists: {policy_name}")]
    PolicyAlreadyExists { policy_name: String },

    #[error("Role already exists: {role_name}")]
    RoleAlreadyExists { role_name: String },

    #[error("Invalid policy condition: {condition}")]
    InvalidCondition { condition: String },

    #[error("Circular role dependency detected: {}", format_role_chain(.role_chain))]
    CircularRoleDependency { role_chain: Vec<String> },

    #[error("Policy parsing error: {source}")]
    ParseError {
        #[from]
        source: pest::error::Error<super::engine::Rule>,
    },

    #[error("Serialization error: {source}")]
    SerializationError {
        #[from]
        source: serde_json::Error,
    },

    #[error("Database error: {source}")]
    DatabaseError {
        #[from]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Configuration error: {details}")]
    ConfigError { details: String },

    #[error("Internal error: {details}")]
    InternalError { details: String },
}

/// Result type for policy operations
pub type PolicyResult<T> = Result<T, PolicyError>;

/// Policy validation errors
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Validation error for '{}': {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Collection of validation errors
#[derive(Debug, Clone, Default)]
pub struct ValidationErrors {
    pub errors: Vec<ValidationError>,
}

impl ValidationErrors {
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    pub fn add(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.errors.push(ValidationError {
            field: field.into(),
            message: message.into(),
        });
    }

    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.errors.len()
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Validation failed with {} errors:", self.errors.len())?;
        for error in &self.errors {
            writeln!(f, "  - {}", error)?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

fn format_role_chain(chain: &[String]) -> String {
    chain.join(" -> ")
}