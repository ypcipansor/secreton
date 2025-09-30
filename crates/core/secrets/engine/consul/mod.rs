use super::{Secret, SecretMetadata, SecretsEngine, SecretsError, EngineMetrics};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// Consul secrets engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulConfig {
    /// Consul server address
    pub address: String,
    /// Consul ACL token for authentication
    pub token: Option<String>,
    /// Default TTL for generated tokens
    pub default_ttl: i64,
    /// Maximum TTL for generated tokens
    pub max_ttl: i64,
}

/// Consul ACL token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulToken {
    /// Token accessor ID
    pub accessor_id: String,
    /// Secret token value
    pub secret_id: String,
    /// Token description
    pub description: String,
    /// Token policies
    pub policies: Vec<String>,
    /// Token roles
    pub roles: Vec<String>,
    /// Token TTL
    pub ttl: i64,
}

/// Consul secrets engine for managing Consul ACL tokens
pub struct ConsulEngine {
    config: ConsulConfig,
    client: reqwest::Client,
}

impl ConsulEngine {
    /// Create new Consul secrets engine
    pub async fn new(config: ConsulConfig) -> Result<Self, SecretsError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SecretsError::InvalidConfiguration(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { config, client })
    }

    /// Create Consul ACL token
    async fn create_consul_token(
        &self,
        description: &str,
        policies: Vec<String>,
        roles: Vec<String>,
        ttl: i64,
    ) -> Result<ConsulToken, SecretsError> {
        let token_data = json!({
            "Description": description,
            "Policies": policies.iter().map(|p| json!({"Name": p})).collect::<Vec<_>>(),
            "Roles": roles.iter().map(|r| json!({"Name": r})).collect::<Vec<_>>(),
            "TTL": format!("{}s", ttl),
        });

        let url = format!("{}/v1/acl/token", self.config.address.trim_end_matches('/'));
        
        let mut request = self.client.put(&url).json(&token_data);
        
        if let Some(token) = &self.config.token {
            request = request.header("X-Consul-Token", token);
        }

        let response = request.send().await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to create Consul token: {}", e)))?;

        if !response.status().is_success() {
            return Err(SecretsError::ExecutionError(format!("Failed to create Consul token: {}", response.status())));
        }

        #[derive(Deserialize)]
        struct ConsulTokenResponse {
            #[serde(rename = "AccessorID")]
            accessor_id: String,
            #[serde(rename = "SecretID")]
            secret_id: String,
        }

        let token_response: ConsulTokenResponse = response.json().await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to parse Consul response: {}", e)))?;

        Ok(ConsulToken {
            accessor_id: token_response.accessor_id,
            secret_id: token_response.secret_id,
            description: description.to_string(),
            policies,
            roles,
            ttl,
        })
    }

    /// Revoke Consul ACL token
    async fn revoke_consul_token(&self, accessor_id: &str) -> Result<(), SecretsError> {
        let url = format!("{}/v1/acl/token/{}", self.config.address.trim_end_matches('/'), accessor_id);
        
        let mut request = self.client.delete(&url);
        
        if let Some(token) = &self.config.token {
            request = request.header("X-Consul-Token", token);
        }

        let response = request.send().await
            .map_err(|e| SecretsError::ExecutionError(format!("Failed to revoke Consul token: {}", e)))?;

        if !response.status().is_success() {
            return Err(SecretsError::ExecutionError(format!("Failed to revoke Consul token: {}", response.status())));
        }

        Ok(())
    }
}

#[async_trait]
impl SecretsEngine for ConsulEngine {
    fn engine_type(&self) -> &'static str {
        "consul"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        let description = data["description"].as_str()
            .unwrap_or("Vault-generated Consul token");
        
        let policies = data["policies"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();
        
        let roles = data["roles"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();
        
        let ttl = data["ttl"].as_i64().unwrap_or(self.config.default_ttl);

        let token = self.create_consul_token(description, policies, roles, ttl).await?;

        let secret_data = json!({
            "token": token.secret_id,
            "accessor": token.accessor_id,
            "policies": token.policies,
            "roles": token.roles,
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
                    ("engine".to_string(), "consul".to_string()),
                ])),
            },
        })
    }

    async fn read_secret(&self, _path: &str) -> Result<Secret, SecretsError> {
        Err(SecretsError::InvalidData("Consul tokens must be regenerated on each access".to_string()))
    }

    async fn update_secret(&self, path: &str, data: Value, options: Option<Value>) -> Result<Secret, SecretsError> {
        self.create_secret(path, data, options).await
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        let accessor_id = path.strip_prefix("consul/creds/")
            .ok_or(SecretsError::InvalidData(format!("Invalid Consul path format: {}", path)))?;
        
        self.revoke_consul_token(accessor_id).await
    }

    async fn list_secrets(&self, _prefix: &str) -> Result<Vec<String>, SecretsError> {
        Ok(vec![])
    }

    async fn collect_metrics(&self) -> Result<EngineMetrics, SecretsError> {
        Ok(EngineMetrics {
            engine_type: "consul".to_string(),
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

impl Default for ConsulConfig {
    fn default() -> Self {
        Self {
            address: "http://localhost:8500".to_string(),
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
    fn test_consul_config_default() {
        let config = ConsulConfig::default();
        assert_eq!(config.address, "http://localhost:8500");
        assert_eq!(config.default_ttl, 3600);
        assert_eq!(config.max_ttl, 86400);
    }

    #[tokio::test]
    async fn test_consul_engine_creation() {
        let config = ConsulConfig::default();
        let engine = ConsulEngine::new(config).await;
        assert!(engine.is_ok());
    }
}
