//! Replication errors

use secreton_errors::SecretonError;

/// Replication-specific errors
#[derive(Debug, thiserror::Error)]
pub enum ReplicationError {
    #[error("Replication not configured")]
    NotConfigured,

    #[error("Already replicating")]
    AlreadyReplicating,

    #[error("Not replicating")]
    NotReplicating,

    #[error("Invalid cluster configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Cluster error: {0}")]
    ClusterError(String),

    #[error("Replication operation error: {0}")]
    ReplicationError(String),
}

impl From<ReplicationError> for SecretonError {
    fn from(err: ReplicationError) -> Self {
        match err {
            ReplicationError::NotConfigured => SecretonError::Internal {
                message: "Replication not configured".to_string(),
            },
            ReplicationError::AlreadyReplicating => SecretonError::Internal {
                message: "Already replicating".to_string(),
            },
            ReplicationError::NotReplicating => SecretonError::Internal {
                message: "Not replicating".to_string(),
            },
            ReplicationError::InvalidConfiguration(msg) => SecretonError::Configuration {
                message: msg,
            },
            ReplicationError::SyncFailed(msg) => SecretonError::Internal {
                message: format!("Sync failed: {}", msg),
            },
            ReplicationError::ConnectionError(msg) => SecretonError::Network {
                message: format!("Connection error: {}", msg),
            },
            ReplicationError::ClusterError(msg) => SecretonError::Internal {
                message: format!("Cluster error: {}", msg),
            },
            ReplicationError::ReplicationError(msg) => SecretonError::Internal {
                message: format!("Replication error: {}", msg),
            },
        }
    }
}

pub type Result<T> = std::result::Result<T, ReplicationError>;