// Core modules
pub mod auth;
pub mod backup;
pub mod config;
pub mod controllers;
pub mod core;
pub mod error;
pub mod k8s;
pub mod key_management;
pub mod models;
pub mod plugins;
pub mod policy;
pub mod routes;
pub mod server;
pub mod secrets;
pub mod services;
pub mod storage;
pub mod utils;
pub mod vault;

// Re-exports
pub use utils::config::Config;
pub use crate::core::AppState;
pub use backup::{
    BackupEngine, BackupConfig, BackupError, RetentionPolicy,
    StorageBackend, LocalStorageBackend, S3StorageBackend
};
pub use policy::{
    Policy, Effect, Condition, Subject, Resource, Action, AuthorizationContext,
    PolicyEngine, PolicyError, PolicyResult
};
pub use key_management::{
    KeyManager, KeyManagerConfig, KeyError, Key, KeyType, KeyData, KeyMetadata,
    KeyStore, SharedKeyStore
};