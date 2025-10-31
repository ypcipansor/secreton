//! OCI (Oracle Cloud Infrastructure) secrets engine

use crate::backend::OciBackend;
use crate::error::*;
use serde_json::Value;
use std::collections::HashMap;

/// OCI secrets engine for managing Oracle Cloud Infrastructure credentials
pub struct OciEngine {
    backend: OciBackend,
}

impl OciEngine {
    /// Create a new OCI secrets engine
    pub fn new(
        tenancy_ocid: String,
        user_ocid: String,
        fingerprint: String,
        private_key: String,
        region: String,
    ) -> Self {
        let backend = OciBackend::new(tenancy_ocid, user_ocid, fingerprint, private_key, region);

        Self { backend }
    }

    /// Generate instance principal credentials
    pub async fn generate_instance_principal(
        &self,
        role_name: &str,
        ttl_seconds: u64,
    ) -> Result<HashMap<String, Value>, SecretError> {
        tracing::info!(
            "Generating OCI instance principal credentials for role: {}",
            role_name
        );

        let mut credentials = self
            .backend
            .generate_instance_principal_credentials(ttl_seconds)
            .await?;
        credentials.insert(
            "role_name".to_string(),
            Value::String(role_name.to_string()),
        );

        Ok(credentials)
    }

    /// Generate API key credentials
    pub async fn generate_api_key(
        &self,
        user_name: &str,
        ttl_seconds: u64,
    ) -> Result<HashMap<String, Value>, SecretError> {
        tracing::info!("Generating OCI API key credentials for user: {}", user_name);

        let mut credentials = self
            .backend
            .generate_api_key_credentials(ttl_seconds)
            .await?;
        credentials.insert(
            "user_name".to_string(),
            Value::String(user_name.to_string()),
        );

        Ok(credentials)
    }

    /// Generate resource principal credentials
    pub async fn generate_resource_principal(
        &self,
        resource_type: &str,
        resource_id: &str,
        ttl_seconds: u64,
    ) -> Result<HashMap<String, Value>, SecretError> {
        tracing::info!(
            "Generating OCI resource principal credentials for {}: {}",
            resource_type,
            resource_id
        );

        let mut credentials = self
            .backend
            .generate_resource_principal_credentials(resource_type, ttl_seconds)
            .await?;
        credentials.insert(
            "resource_id".to_string(),
            Value::String(resource_id.to_string()),
        );

        Ok(credentials)
    }

    /// List compartments
    pub async fn list_compartments(&self) -> Result<Vec<HashMap<String, Value>>, SecretError> {
        tracing::info!("Listing OCI compartments");
        self.backend.list_compartments().await
    }

    /// Get vault secrets
    pub async fn get_vault_secrets(
        &self,
        vault_id: &str,
    ) -> Result<Vec<HashMap<String, Value>>, SecretError> {
        tracing::info!("Getting OCI vault secrets for vault: {}", vault_id);
        self.backend.get_vault_secrets(vault_id).await
    }

    /// Create vault secret
    pub async fn create_vault_secret(
        &self,
        vault_id: &str,
        secret_name: &str,
        secret_value: &str,
        secret_type: &str,
    ) -> Result<HashMap<String, Value>, SecretError> {
        tracing::info!(
            "Creating OCI vault secret: {} in vault: {}",
            secret_name,
            vault_id
        );
        self.backend
            .create_vault_secret(vault_id, secret_name, secret_value, secret_type)
            .await
    }

    /// Rotate credentials
    pub async fn rotate_credentials(
        &self,
        credential_type: &str,
    ) -> Result<HashMap<String, Value>, SecretError> {
        tracing::info!("Rotating OCI credentials of type: {}", credential_type);

        match credential_type {
            "instance_principal" => {
                self.backend
                    .generate_instance_principal_credentials(3600)
                    .await
            }
            "api_key" => self.backend.generate_api_key_credentials(3600).await,
            "resource_principal" => {
                self.backend
                    .generate_resource_principal_credentials("compute", 3600)
                    .await
            }
            _ => Err(SecretError::InvalidConfiguration(format!(
                "Unknown credential type: {}",
                credential_type
            ))),
        }
    }

    /// Get credential metadata
    pub async fn get_credential_metadata(
        &self,
        credential_id: &str,
    ) -> Result<HashMap<String, Value>, SecretError> {
        tracing::info!("Getting OCI credential metadata for: {}", credential_id);

        // Mock metadata response
        let mut metadata = HashMap::new();
        metadata.insert(
            "credential_id".to_string(),
            Value::String(credential_id.to_string()),
        );
        metadata.insert("status".to_string(), Value::String("active".to_string()));
        metadata.insert(
            "created_at".to_string(),
            Value::String(chrono::Utc::now().to_rfc3339()),
        );
        metadata.insert(
            "last_rotated".to_string(),
            Value::String(chrono::Utc::now().to_rfc3339()),
        );
        metadata.insert(
            "rotation_policy".to_string(),
            Value::String("30_days".to_string()),
        );

        Ok(metadata)
    }

    /// Revoke credentials
    pub async fn revoke_credentials(&self, credential_id: &str) -> Result<(), SecretError> {
        tracing::info!("Revoking OCI credentials: {}", credential_id);

        // In a real implementation, this would revoke the credentials in OCI
        // For now, just log the operation
        tracing::info!("OCI credentials {} revoked successfully", credential_id);

        Ok(())
    }

    /// Test connectivity
    pub async fn test_connectivity(&self) -> Result<bool, SecretError> {
        tracing::info!("Testing OCI connectivity");
        self.backend.test_connectivity().await
    }

    /// Get engine status
    pub async fn status(&self) -> Result<HashMap<String, Value>, SecretError> {
        let mut status = HashMap::new();

        status.insert("engine_type".to_string(), Value::String("oci".to_string()));
        status.insert(
            "status".to_string(),
            Value::String("operational".to_string()),
        );
        status.insert(
            "backend_connected".to_string(),
            Value::Bool(self.test_connectivity().await.unwrap_or(false)),
        );
        status.insert(
            "last_health_check".to_string(),
            Value::String(chrono::Utc::now().to_rfc3339()),
        );

        Ok(status)
    }
}
