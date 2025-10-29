//! Storage types and data structures
//!
//! This module contains the core data structures used throughout the storage system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Core storage entry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Audit log entry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub user: Option<String>,
    pub action: Option<String>,
    pub path: Option<String>,
    pub status: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
}

/// Supported storage backend types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    InMemory,
    Postgres,
    MySQL,
    MongoDB,
    Redis,
    S3,
    GCS,
    AzureBlob,
    Cassandra,
    CockroachDB,
    Raft,
}