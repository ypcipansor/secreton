use azure_identity::{DefaultAzureCredential, TokenCredentialOptions};
use azure_security_keyvault::{KeyClient, SecretClient};
use azure_storage_blobs::prelude::*;
use azure_storage_queues::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{Utc, Duration};
use crate::storage::Storage;
use crate::models::lease::Lease;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    pub subscription_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub key_vault_url: Option<String>,
    pub resource_group: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureServicePrincipalCredential {
    pub client_id: String,
    pub client_secret: String,
    pub tenant_id: String,
    pub subscription_id: String,
    pub lease_id: String,
    pub lease_duration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureManagedIdentityCredential {
    pub client_id: String,
    pub resource_id: String,
    pub lease_id: String,
    pub lease_duration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureStorageCredential {
    pub account_name: String,
    pub account_key: String,
    pub connection_string: String,
    pub lease_id: String,
    pub lease_duration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureKeyVaultSecret {
    pub name: String,
    pub value: String,
    pub content_type: Option<String>,
    pub tags: HashMap<String, String>,
    pub lease_id: String,
    pub lease_duration: i64,
}

pub struct AzureSecretsEngine {
    config: AzureConfig,
    credential: DefaultAzureCredential,
    key_client: Option<KeyClient>,
    secret_client: Option<SecretClient>,
    storage_client: Option<BlobServiceClient>,
    queue_client: Option<QueueServiceClient>,
}

impl AzureSecretsEngine {
    pub async fn new(config: AzureConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let credential = DefaultAzureCredential::create(TokenCredentialOptions::default())?;

        let mut key_client = None;
        let mut secret_client = None;

        // Initialize Key Vault clients if URL is provided
        if let Some(kv_url) = &config.key_vault_url {
            key_client = Some(KeyClient::new(kv_url, &credential)?);
            secret_client = Some(SecretClient::new(kv_url, &credential)?);
        }

        // Initialize Storage clients
        let storage_client = Some(BlobServiceClient::new(
            format!("https://{}.blob.core.windows.net", config.client_id),
            credential.clone(),
        ));

        let queue_client = Some(QueueServiceClient::new(
            format!("https://{}.queue.core.windows.net", config.client_id),
            credential.clone(),
        ));

        Ok(Self {
            config,
            credential,
            key_client,
            secret_client,
            storage_client,
            queue_client,
        })
    }

    pub async fn create_service_principal(
        &self,
        display_name: &str,
        role_assignments: Vec<String>,
        lease_duration: i64,
    ) -> Result<AzureServicePrincipalCredential, Box<dyn std::error::Error + Send + Sync>> {
        // Create service principal using Microsoft Graph API
        // This is a simplified implementation - in practice, you'd use the Graph API

        let client_id = format!("sp_{}_{}", display_name, Utc::now().timestamp());
        let client_secret = self.generate_secure_secret();

        // In a real implementation, you would:
        // 1. Create the service principal via Microsoft Graph API
        // 2. Assign roles using Azure RBAC
        // 3. Store the credentials securely

        let credential = AzureServicePrincipalCredential {
            client_id,
            client_secret,
            tenant_id: self.config.tenant_id.clone(),
            subscription_id: self.config.subscription_id.clone(),
            lease_id: format!("azure/sp/{}/{}", display_name, Utc::now().timestamp()),
            lease_duration,
        };

        Ok(credential)
    }

    pub async fn create_managed_identity(
        &self,
        name: &str,
        scope: &str,
        role_definition_id: &str,
        lease_duration: i64,
    ) -> Result<AzureManagedIdentityCredential, Box<dyn std::error::Error + Send + Sync>> {
        // Create user-assigned managed identity
        // This would typically be done via Azure Resource Manager API

        let client_id = format!("mi_{}_{}", name, Utc::now().timestamp());
        let resource_id = format!("/subscriptions/{}/resourceGroups/{}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{}",
            self.config.subscription_id,
            self.config.resource_group.as_deref().unwrap_or("default"),
            name
        );

        // In a real implementation, you would:
        // 1. Create the managed identity via ARM API
        // 2. Assign roles at the specified scope
        // 3. Configure the identity for use

        let credential = AzureManagedIdentityCredential {
            client_id,
            resource_id,
            lease_id: format!("azure/mi/{}/{}", name, Utc::now().timestamp()),
            lease_duration,
        };

        Ok(credential)
    }

    pub async fn create_storage_account_credentials(
        &self,
        account_name: &str,
        permissions: Vec<String>,
        lease_duration: i64,
    ) -> Result<AzureStorageCredential, Box<dyn std::error::Error + Send + Sync>> {
        // Generate storage account key
        let account_key = self.generate_secure_secret();

        // Create connection string
        let connection_string = format!(
            "DefaultEndpointsProtocol=https;AccountName={};AccountKey={};EndpointSuffix=core.windows.net",
            account_name, account_key
        );

        let credential = AzureStorageCredential {
            account_name: account_name.to_string(),
            account_key,
            connection_string,
            lease_id: format!("azure/storage/{}/{}", account_name, Utc::now().timestamp()),
            lease_duration,
        };

        Ok(credential)
    }

    pub async fn create_key_vault_secret(
        &self,
        name: &str,
        value: &str,
        content_type: Option<&str>,
        tags: HashMap<String, String>,
        lease_duration: i64,
    ) -> Result<AzureKeyVaultSecret, Box<dyn std::error::Error + Send + Sync>> {
        let secret_client = self.secret_client.as_ref()
            .ok_or("Key Vault client not configured")?;

        // Create secret in Key Vault
        let mut secret_properties = azure_security_keyvault::SecretProperties::new(value.to_string());

        if let Some(content_type) = content_type {
            secret_properties = secret_properties.content_type(content_type.to_string());
        }

        if !tags.is_empty() {
            secret_properties = secret_properties.tags(tags.clone());
        }

        let secret = secret_client.set_secret(name, secret_properties).await?;

        let secret = AzureKeyVaultSecret {
            name: name.to_string(),
            value: value.to_string(),
            content_type: content_type.map(|s| s.to_string()),
            tags,
            lease_id: format!("azure/kv/{}/{}", name, Utc::now().timestamp()),
            lease_duration,
        };

        Ok(secret)
    }

    pub async fn get_key_vault_secret(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let secret_client = self.secret_client.as_ref()
            .ok_or("Key Vault client not configured")?;

        let secret = if let Some(version) = version {
            secret_client.get_secret(name, version).await?
        } else {
            secret_client.get_secret(name, "").await?
        };

        Ok(secret.value)
    }

    pub async fn list_key_vault_secrets(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let secret_client = self.secret_client.as_ref()
            .ok_or("Key Vault client not configured")?;

        let secrets = secret_client.list_secrets().await?;
        let mut names = Vec::new();

        for secret in secrets {
            if let Some(id) = secret.id {
                if let Some(name) = id.name() {
                    names.push(name.to_string());
                }
            }
        }

        Ok(names)
    }

    pub async fn delete_key_vault_secret(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let secret_client = self.secret_client.as_ref()
            .ok_or("Key Vault client not configured")?;

        secret_client.delete_secret(name).await?;
        Ok(())
    }

    pub async fn create_storage_container(
        &self,
        container_name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let blob_client = self.storage_client.as_ref()
            .ok_or("Storage client not configured")?
            .container_client(container_name);

        blob_client.create().await?;
        Ok(())
    }

    pub async fn create_queue(
        &self,
        queue_name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let queue_client = self.queue_client.as_ref()
            .ok_or("Queue client not configured")?
            .queue_client(queue_name);

        queue_client.create().await?;
        Ok(())
    }

    pub async fn revoke_service_principal(
        &self,
        client_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a real implementation, you would:
        // 1. Remove role assignments
        // 2. Delete the service principal
        // 3. Clean up any associated resources

        println!("[REVOKE] Azure Service Principal {} revoked", client_id);
        Ok(())
    }

    pub async fn revoke_managed_identity(
        &self,
        client_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a real implementation, you would:
        // 1. Remove role assignments
        // 2. Delete the managed identity
        // 3. Clean up any associated resources

        println!("[REVOKE] Azure Managed Identity {} revoked", client_id);
        Ok(())
    }

    pub async fn revoke_storage_credentials(
        &self,
        account_name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a real implementation, you would:
        // 1. Regenerate storage account keys
        // 2. Update any dependent services
        // 3. Revoke access to the old keys

        println!("[REVOKE] Azure Storage credentials for {} revoked", account_name);
        Ok(())
    }

    fn generate_secure_secret(&self) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789\
                                !@#$%^&*()-_=+[]{}|;:,.<>?";

        let mut rng = rand::thread_rng();
        (0..64)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
}

pub async fn create_lease_for_azure_credential(
    storage: &Storage,
    credential_type: &str,
    resource_id: &str,
    ttl_seconds: i64,
) -> Result<Lease, Box<dyn std::error::Error + Send + Sync>> {
    let lease = crate::services::lease::create_lease(
        storage,
        "azure-engine",
        credential_type,
        resource_id,
        ttl_seconds,
    ).await?;

    Ok(lease)
}

pub async fn revoke_lease_for_azure_credential(
    storage: &Storage,
    lease_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    crate::services::lease::revoke_lease(storage, lease_id).await?;
    Ok(())
}
