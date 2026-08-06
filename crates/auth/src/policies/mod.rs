//! # Secreton Policies Engine
//!
//! This crate provides comprehensive policy management and evaluation for the Secreton secreton system.
//! It implements RBAC (Role-Based Access Control) and ABAC (Attribute-Based Access Control) with
//! a flexible policy language and evaluation engine.
//!
//! ## Features
//!
//! - **RBAC**: Role-based access control with hierarchical roles
//! - **ABAC**: Attribute-based access control with flexible conditions
//! - **Policy Language**: Domain-specific language for policy definition
//! - **Policy Evaluation**: High-performance policy evaluation engine
//! - **Audit Logging**: Comprehensive audit trails for policy decisions
//!
//! ## Architecture
//!
//! The policies crate follows domain-driven design principles:
//!
//! - `engine/`: Core policy evaluation engine
//! - `evaluator/`: Policy evaluation logic and decision making
//! - `model/`: Policy data models and DTOs
//! - `service/`: Policy management services
//! - `error/`: Policy-specific error types

pub mod engine;
pub mod error;
pub mod evaluator;
pub mod model;
pub mod service;

pub use engine::*;
pub use error::{PolicyResult, ValidationError, ValidationErrors};
pub use evaluator::*;
pub use model::*;
pub use secreton_domain::SecretonError;
pub use service::*;
