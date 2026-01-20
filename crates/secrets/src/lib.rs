//! # Secreton Secrets Engine
//!
//! This crate provides the secret engines and backends for the Secreton system.
//! It consolidates all secret engine implementations into a single, well-structured domain.
//!
//! ## Supported Engines
//!
//! - **KV v2**: Versioned key-value storage with rollback capabilities
//! - **Transit**: Encryption/decryption as a service with key management
//! - **Database**: Dynamic database credentials generation
//! - **AWS**: AWS secret management integration
//! - **PKI**: Certificate authority and certificate management
//! - **SSH**: SSH key signing and management
//! - **TOTP**: Time-based one-time password generation
//! - **RabbitMQ**: RabbitMQ credential management
//! - **MongoDB**: MongoDB credential management
//! - **LDAP**: LDAP authentication integration
//!
//! ## Architecture
//!
//! The secrets crate follows domain-driven design principles:
//!
//! - `engine/`: Core secret engine implementations
//! - `backend/`: Storage backend integrations
//! - `model/`: Data models and DTOs
//! - `service/`: Business logic services
//! - `error/`: Secret-specific error types

pub mod backend;
pub mod engine;
pub mod error;
pub mod model;
pub mod service;
pub mod storage;

pub use backend::{
    AwsBackend, MongodbBackend, MysqlBackend, OciBackend, PostgresBackend, SecretBackend,
};
pub use engine::{
    AwsEngine, DatabaseEngine, KvEngine, LdapEngine, MongodbEngine, OciEngine, PkiEngine,
    RabbitmqEngine, SshEngine, TotpEngine, TransitEngine,
};
pub use error::*;
pub use model::*;
pub use service::*;
pub use storage::*;
