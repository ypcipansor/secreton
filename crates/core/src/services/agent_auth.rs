//! Agent Auto-Auth
//!
//! Automatic authentication for Vault agents with configurable auth methods
//! and sinks for credential delivery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Agent auth errors
#[derive(Debug, thiserror::Error)]
pub enum AgentAuthError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Sink write failed: {0}")]
    SinkWriteFailed(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    
    #[error("Token renewal failed: {0}")]
    RenewalFailed(String),
}

/// Auto-auth method types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AutoAuthMethod {
    /// AWS IAM authentication
    Aws {
        role: String,
        region: Option<String>,
    },
    
    /// Kubernetes service account
    Kubernetes {
        role: String,
        token_path: String,
    },
    
    /// AppRole
    AppRole {
        role_id: String,
        secret_id_path: Option<String>,
    },
    
    /// Certificate authentication
    Certificate {
        cert_path: String,
        key_path: String,
        name: Option<String>,
    },
}

/// Sink types for credential delivery
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SinkType {
    /// Write to file
    File {
        path: String,
        mode: Option<u32>, // File permissions
    },
    
    /// Store in memory (for testing)
    Memory,
    
    /// Response wrapping
    ResponseWrapping {
        ttl: u64,
    },
}

/// Sink configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkConfig {
    /// Sink type
    pub sink_type: SinkType,
    
    /// Response wrapping for this sink
    pub wrap_ttl: Option<u64>,
    
    /// DH (Diffie-Hellman) parameters for encryption
    pub dh_type: Option<String>,
    
    /// DH path for public key
    pub dh_path: Option<String>,
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Auto-auth method
    pub method: AutoAuthMethod,
    
    /// Sinks for token delivery
    pub sinks: Vec<SinkConfig>,
    
    /// Exit on error
    pub exit_on_err: bool,
    
    /// Keep alive duration (seconds)
    pub keep_alive_duration: Option<u64>,
}

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// Client token
    pub client_token: String,
    
    /// Accessor
    pub accessor: String,
    
    /// Policies
    pub policies: Vec<String>,
    
    /// Renewable
    pub renewable: bool,
    
    /// Lease duration
    pub lease_duration: u64,
    
    /// Metadata
    pub metadata: HashMap<String, String>,
    
    /// Created at
    pub created_at: DateTime<Utc>,
}

/// Sink write result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkWriteResult {
    /// Sink index
    pub sink_index: usize,
    
    /// Success
    pub success: bool,
    
    /// Error message
    pub error: Option<String>,
    
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Agent auto-auth service
pub struct AgentAuth {
    config: Arc<RwLock<Option<AgentConfig>>>,
    current_token: Arc<RwLock<Option<AuthResult>>>,
    memory_sink: Arc<RwLock<Option<String>>>, // For testing
}

impl AgentAuth {
    /// Create new agent auth service
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            current_token: Arc::new(RwLock::new(None)),
            memory_sink: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Configure agent
    pub async fn configure(&self, config: AgentConfig) -> Result<(), AgentAuthError> {
        // Validate configuration
        if config.sinks.is_empty() {
            return Err(AgentAuthError::InvalidConfiguration(
                "At least one sink must be configured".to_string()
            ));
        }
        
        let mut current_config = self.config.write().await;
        *current_config = Some(config);
        Ok(())
    }
    
    /// Perform authentication
    pub async fn authenticate(&self) -> Result<AuthResult, AgentAuthError> {
        let config = self.config.read().await;
        let config = config.as_ref()
            .ok_or_else(|| AgentAuthError::InvalidConfiguration("No configuration set".to_string()))?;
        
        // Perform authentication based on method
        let auth_result = match &config.method {
            AutoAuthMethod::Aws { role, region } => {
                self.authenticate_aws(role, region.as_deref()).await?
            }
            AutoAuthMethod::Kubernetes { role, token_path } => {
                self.authenticate_kubernetes(role, token_path).await?
            }
            AutoAuthMethod::AppRole { role_id, secret_id_path } => {
                self.authenticate_approle(role_id, secret_id_path.as_deref()).await?
            }
            AutoAuthMethod::Certificate { cert_path, key_path, name } => {
                self.authenticate_certificate(cert_path, key_path, name.as_deref()).await?
            }
        };
        
        // Store current token
        let mut current_token = self.current_token.write().await;
        *current_token = Some(auth_result.clone());
        
        Ok(auth_result)
    }
    
    /// Write to sinks
    pub async fn write_to_sinks(&self, token: &str) -> Result<Vec<SinkWriteResult>, AgentAuthError> {
        let config = self.config.read().await;
        let config = config.as_ref()
            .ok_or_else(|| AgentAuthError::InvalidConfiguration("No configuration set".to_string()))?;
        
        let mut results = Vec::new();
        
        for (index, sink) in config.sinks.iter().enumerate() {
            let result = match self.write_to_sink(sink, token).await {
                Ok(_) => SinkWriteResult {
                    sink_index: index,
                    success: true,
                    error: None,
                    timestamp: Utc::now(),
                },
                Err(e) => SinkWriteResult {
                    sink_index: index,
                    success: false,
                    error: Some(e.to_string()),
                    timestamp: Utc::now(),
                },
            };
            
            // Exit on error if configured (check before push to avoid borrow issue)
            if !result.success && config.exit_on_err {
                let error_msg = result.error.clone().unwrap_or_default();
                results.push(result);
                return Err(AgentAuthError::SinkWriteFailed(error_msg));
            }
            
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Write to single sink
    async fn write_to_sink(&self, sink: &SinkConfig, token: &str) -> Result<(), AgentAuthError> {
        match &sink.sink_type {
            SinkType::File { path, mode: _ } => {
                // In production, write to file with proper permissions
                // For now, simulate
                if path.is_empty() {
                    return Err(AgentAuthError::SinkWriteFailed("Empty file path".to_string()));
                }
                Ok(())
            }
            SinkType::Memory => {
                let mut memory = self.memory_sink.write().await;
                *memory = Some(token.to_string());
                Ok(())
            }
            SinkType::ResponseWrapping { ttl: _ } => {
                // In production, wrap token in response wrapping
                Ok(())
            }
        }
    }
    
    /// Renew token
    pub async fn renew_token(&self) -> Result<AuthResult, AgentAuthError> {
        // Clone the current token to avoid holding read lock while acquiring write lock
        let current_clone = {
            let current = self.current_token.read().await;
            current.clone()
        };
        
        let current = current_clone.as_ref()
            .ok_or_else(|| AgentAuthError::RenewalFailed("No token to renew".to_string()))?;
        
        if !current.renewable {
            return Err(AgentAuthError::RenewalFailed("Token not renewable".to_string()));
        }
        
        // In production, call Vault API to renew token
        // For now, return current token with updated timestamp
        let renewed = AuthResult {
            created_at: Utc::now(),
            ..current.clone()
        };
        
        let mut current_token = self.current_token.write().await;
        *current_token = Some(renewed.clone());
        
        Ok(renewed)
    }
    
    /// Get current token
    pub async fn get_current_token(&self) -> Option<AuthResult> {
        let token = self.current_token.read().await;
        token.clone()
    }
    
    /// Get memory sink value (for testing)
    pub async fn get_memory_sink(&self) -> Option<String> {
        let memory = self.memory_sink.read().await;
        memory.clone()
    }
    
    // Authentication method implementations (simulated)
    
    async fn authenticate_aws(&self, role: &str, _region: Option<&str>) -> Result<AuthResult, AgentAuthError> {
        // In production: get AWS credentials, sign request, call Vault
        Ok(AuthResult {
            client_token: format!("aws-token-{}", uuid::Uuid::new_v4()),
            accessor: uuid::Uuid::new_v4().to_string(),
            policies: vec!["default".to_string(), format!("{}-policy", role)],
            renewable: true,
            lease_duration: 3600,
            metadata: HashMap::from([
                ("auth_method".to_string(), "aws".to_string()),
                ("role".to_string(), role.to_string()),
            ]),
            created_at: Utc::now(),
        })
    }
    
    async fn authenticate_kubernetes(&self, role: &str, _token_path: &str) -> Result<AuthResult, AgentAuthError> {
        // In production: read service account token, call Vault
        Ok(AuthResult {
            client_token: format!("k8s-token-{}", uuid::Uuid::new_v4()),
            accessor: uuid::Uuid::new_v4().to_string(),
            policies: vec!["default".to_string(), format!("{}-policy", role)],
            renewable: true,
            lease_duration: 3600,
            metadata: HashMap::from([
                ("auth_method".to_string(), "kubernetes".to_string()),
                ("role".to_string(), role.to_string()),
            ]),
            created_at: Utc::now(),
        })
    }
    
    async fn authenticate_approle(&self, role_id: &str, _secret_id_path: Option<&str>) -> Result<AuthResult, AgentAuthError> {
        // In production: read secret ID, call Vault
        Ok(AuthResult {
            client_token: format!("approle-token-{}", uuid::Uuid::new_v4()),
            accessor: uuid::Uuid::new_v4().to_string(),
            policies: vec!["default".to_string()],
            renewable: true,
            lease_duration: 3600,
            metadata: HashMap::from([
                ("auth_method".to_string(), "approle".to_string()),
                ("role_id".to_string(), role_id.to_string()),
            ]),
            created_at: Utc::now(),
        })
    }
    
    async fn authenticate_certificate(&self, _cert_path: &str, _key_path: &str, name: Option<&str>) -> Result<AuthResult, AgentAuthError> {
        // In production: load certificate, call Vault with mTLS
        Ok(AuthResult {
            client_token: format!("cert-token-{}", uuid::Uuid::new_v4()),
            accessor: uuid::Uuid::new_v4().to_string(),
            policies: vec!["default".to_string()],
            renewable: true,
            lease_duration: 3600,
            metadata: HashMap::from([
                ("auth_method".to_string(), "cert".to_string()),
                ("cert_name".to_string(), name.unwrap_or("default").to_string()),
            ]),
            created_at: Utc::now(),
        })
    }
}

impl Default for AgentAuth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_aws_auto_auth() {
        let agent = AgentAuth::new();
        
        let config = AgentConfig {
            method: AutoAuthMethod::Aws {
                role: "test-role".to_string(),
                region: Some("us-east-1".to_string()),
            },
            sinks: vec![
                SinkConfig {
                    sink_type: SinkType::Memory,
                    wrap_ttl: None,
                    dh_type: None,
                    dh_path: None,
                }
            ],
            exit_on_err: false,
            keep_alive_duration: Some(3600),
        };
        
        agent.configure(config).await.unwrap();
        
        let result = agent.authenticate().await.unwrap();
        assert!(result.client_token.starts_with("aws-token-"));
        assert!(result.policies.contains(&"test-role-policy".to_string()));
    }
    
    #[tokio::test]
    async fn test_file_sink() {
        let agent = AgentAuth::new();
        
        let config = AgentConfig {
            method: AutoAuthMethod::Kubernetes {
                role: "test-role".to_string(),
                token_path: "/var/run/secrets/token".to_string(),
            },
            sinks: vec![
                SinkConfig {
                    sink_type: SinkType::File {
                        path: "/tmp/vault-token".to_string(),
                        mode: Some(0o600),
                    },
                    wrap_ttl: None,
                    dh_type: None,
                    dh_path: None,
                }
            ],
            exit_on_err: true,
            keep_alive_duration: None,
        };
        
        agent.configure(config).await.unwrap();
        
        let auth_result = agent.authenticate().await.unwrap();
        let sink_results = agent.write_to_sinks(&auth_result.client_token).await.unwrap();
        
        assert_eq!(sink_results.len(), 1);
        assert!(sink_results[0].success);
    }
    
    #[tokio::test]
    async fn test_memory_sink() {
        let agent = AgentAuth::new();
        
        let config = AgentConfig {
            method: AutoAuthMethod::AppRole {
                role_id: "test-role-id".to_string(),
                secret_id_path: Some("/path/to/secret".to_string()),
            },
            sinks: vec![
                SinkConfig {
                    sink_type: SinkType::Memory,
                    wrap_ttl: None,
                    dh_type: None,
                    dh_path: None,
                }
            ],
            exit_on_err: false,
            keep_alive_duration: None,
        };
        
        agent.configure(config).await.unwrap();
        
        let auth_result = agent.authenticate().await.unwrap();
        agent.write_to_sinks(&auth_result.client_token).await.unwrap();
        
        let stored_token = agent.get_memory_sink().await.unwrap();
        assert_eq!(stored_token, auth_result.client_token);
    }
    
    #[tokio::test]
    async fn test_token_renewal() {
        let agent = AgentAuth::new();
        
        let config = AgentConfig {
            method: AutoAuthMethod::Certificate {
                cert_path: "/path/to/cert.pem".to_string(),
                key_path: "/path/to/key.pem".to_string(),
                name: Some("test-cert".to_string()),
            },
            sinks: vec![
                SinkConfig {
                    sink_type: SinkType::Memory,
                    wrap_ttl: None,
                    dh_type: None,
                    dh_path: None,
                }
            ],
            exit_on_err: false,
            keep_alive_duration: Some(1800),
        };
        
        agent.configure(config).await.unwrap();
        
        agent.authenticate().await.unwrap();
        
        let renewed = agent.renew_token().await.unwrap();
        assert!(renewed.renewable);
        assert_eq!(renewed.lease_duration, 3600);
    }
}
