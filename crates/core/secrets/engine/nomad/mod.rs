use super::{Secret, SecretMetadata, SecretsEngine, SecretsError, EngineMetrics};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// Nomad secrets engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NomadConfig {
    /// Nomad server address
    pub address: String,
    /// Nomad management token
    pub token: Option<String>,
    /// Default TTL for generated tokens
    pub default_ttl: i64,
    /// Maximum TTL for generated tokens
    pub max_ttl: i64,
}

/// Nomad ACL token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NomadToken {
    /// Token accessor ID
    pub accessor_id: String,
    /// Secret token value
    pub secret_id: String,
    /// Token name
    pub name: String,
    /// Token type (client, management)
    pub token_type: String,
    /// Token policies
    pub policies: Vec<String>,
    /// Token TTL
    pub ttl: i64,
}

/// Nomad secrets engine for managing Nomad ACL tokens
pub struct NomadEngine {
    config: NomadConfig,
    client: reqwest::Client,
}

impl NomadEngine {
    /// Create new Nomad secrets engine
    pub async fn new(config: NomadConfig) -> Result<Self, SecretsError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SecretsError::InvalidConfiguration(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { config, client })
    }

    /// Create Nomad ACL token
    async fn create_nomad_token(
        &self,
        name: &str,
        token_type: &str,
        policies: Vec<String>,
        ttl: i64,
    ) -> Result<NomadToken, SecretsError> {
        let token_data = json!({
            "Name": name,
            "Type": token_type,
            "Policies": policies,
            "TTL": format!("{}s", ttl),
        });

        let url = format!("{}/v1/acl/token", self.config.address.trim_end_matches('/'));
        
        let mut request = self.client.post(&url).json(&token_data);
        
        if let Some(token) = &self.config.token {
            request = request.header("X-Nomad-Token", token);
        }

        let response = request.send().await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to create Nomad token: {}", e)))?;

        if !response.status().is_success() {
            return Err(SecretsError::ExecutionError(format!("Failed to create Nomad token: {}", response.status())));
        }

        #[derive(Deserialize)]
        struct NomadTokenResponse {
            #[serde(rename = "AccessorID")]
            accessor_id: String,
            #[serde(rename = "SecretID")]
            secret_id: String,
        }

        let token_response: NomadTokenResponse = response.json().await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to parse Nomad response: {}", e)))?;

        Ok(NomadToken {
            accessor_id: token_response.accessor_id,
            secret_id: token_response.secret_id,
            name: name.to_string(),
            token_type: token_type.to_string(),
            policies,
            ttl,
        })
    }

    /// Revoke Nomad ACL token
    async fn revoke_nomad_token(&self, accessor_id: &str) -> Result<(), SecretsError> {
        let url = format!("{}/v1/acl/token/{}", self.config.address.trim_end_matches('/'), accessor_id);
        
        let mut request = self.client.delete(&url);
        
        if let Some(token) = &self.config.token {
            request = request.header("X-Nomad-Token", token);
        }

        let response = request.send().await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to revoke Nomad token: {}", e)))?;

        if !response.status().is_success() {
            return Err(SecretsError::ExecutionError(format!("Failed to revoke Nomad token: {}", response.status())));
        }

        Ok(())
    }
}

#[async_trait]
impl SecretsEngine for NomadEngine {
    fn engine_type(&self) -> &'static str {
        "nomad"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        let name = data["name"].as_str()
            .unwrap_or("vault-generated-token");
        
        let token_type = data["type"].as_str()
            .unwrap_or("client");
        
        let policies = data["policies"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();
        
        let ttl = data["ttl"].as_i64().unwrap_or(self.config.default_ttl);

        let token = self.create_nomad_token(name, token_type, policies, ttl).await?;

        let secret_data = json!({
            "token": token.secret_id,
            "accessor": token.accessor_id,
            "name": token.name,
            "type": token.token_type,
            "policies": token.policies,
        });

        Ok(Secret {
            id: Uuid::new_v4(),
            path: path.to_string(),
            data: secret_data,
            metadata: SecretMetadata {
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: 1,
                ttl: Some(ttl),
                expired_at: Some(Utc::now() + chrono::Duration::seconds(ttl)),
                custom_metadata: Some(HashMap::from([
                    ("accessor_id".to_string(), token.accessor_id),
                    ("engine".to_string(), "nomad".to_string()),
                ])),
            },
        })
    }

    async fn read_secret(&self, _path: &str) -> Result<Secret, SecretsError> {
        Err(SecretsError::InvalidData("Nomad tokens must be regenerated on each access".to_string()))
    }

    async fn update_secret(&self, path: &str, data: Value, options: Option<Value>) -> Result<Secret, SecretsError> {
        self.create_secret(path, data, options).await
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        let accessor_id = path.strip_prefix("nomad/creds/")
            .ok_or(SecretsError::InvalidData(format!("Invalid Nomad path format: {}", path)))?;
        
        self.revoke_nomad_token(accessor_id).await
    }

    async fn list_secrets(&self, _prefix: &str) -> Result<Vec<String>, SecretsError> {
        Ok(vec![])
    }

    async fn collect_metrics(&self) -> Result<EngineMetrics, SecretsError> {
        Ok(EngineMetrics {
            engine_type: "nomad".to_string(),
            secrets_created: 0,
            secrets_read: 0,
            secrets_updated: 0,
            secrets_deleted: 0,
            avg_response_time_ms: 0.0,
            error_count: 0,
            active_secrets: 0,
            storage_size_bytes: 0,
        })
    }
}

impl Default for NomadConfig {
    fn default() -> Self {
        Self {
            address: "http://localhost:4646".to_string(),
            token: None,
            default_ttl: 3600,
            max_ttl: 86400,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nomad_config_default() {
        let config = NomadConfig::default();
        assert_eq!(config.address, "http://localhost:4646");
        assert_eq!(config.default_ttl, 3600);
        assert_eq!(config.max_ttl, 86400);
    }

    #[tokio::test]
    async fn test_nomad_engine_creation() {
        let config = NomadConfig::default();
        let engine = NomadEngine::new(config).await;
        assert!(engine.is_ok());
    }
}
