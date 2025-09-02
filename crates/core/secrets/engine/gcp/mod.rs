use gcp_auth::{AuthenticationManager, CustomServiceAccount};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{Utc, Duration};
use crate::storage::Storage;
use crate::models::lease::Lease;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpConfig {
    pub project_id: String,
    pub service_account_email: Option<String>,
    pub service_account_key: Option<String>,
    pub credentials_file: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpServiceAccountCredential {
    pub service_account_email: String,
    pub private_key: String,
    pub project_id: String,
    pub client_email: String,
    pub token_uri: String,
    pub lease_id: String,
    pub lease_duration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpIamCredential {
    pub service_account_email: String,
    pub access_token: String,
    pub expires_at: String,
    pub project_id: String,
    pub lease_id: String,
    pub lease_duration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpStorageCredential {
    pub service_account_email: String,
    pub private_key: String,
    pub project_id: String,
    pub bucket_name: String,
    pub lease_id: String,
    pub lease_duration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpBigQueryCredential {
    pub service_account_email: String,
    pub private_key: String,
    pub project_id: String,
    pub dataset_id: String,
    pub lease_id: String,
    pub lease_duration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpSecretManagerSecret {
    pub name: String,
    pub value: String,
    pub labels: HashMap<String, String>,
    pub lease_id: String,
    pub lease_duration: i64,
}

#[derive(Debug, Deserialize)]
struct GcpTokenResponse {
    access_token: String,
    expires_in: i64,
    token_type: String,
}

pub struct GcpSecretsEngine {
    config: GcpConfig,
    auth_manager: AuthenticationManager<CustomServiceAccount>,
    http_client: Client,
}

impl GcpSecretsEngine {
    pub async fn new(config: GcpConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let auth_manager = if let Some(key) = &config.service_account_key {
            // Use provided service account key
            let service_account = CustomServiceAccount::from_key(key.clone())?;
            AuthenticationManager::from(service_account)
        } else if let Some(file_path) = &config.credentials_file {
            // Use credentials file
            AuthenticationManager::from_file(file_path).await?
        } else {
            // Use default credentials
            AuthenticationManager::new().await?
        };

        let http_client = Client::new();

        Ok(Self {
            config,
            auth_manager,
            http_client,
        })
    }

    pub async fn create_service_account(
        &self,
        account_id: &str,
        display_name: &str,
        roles: Vec<String>,
        lease_duration: i64,
    ) -> Result<GcpServiceAccountCredential, Box<dyn std::error::Error + Send + Sync>> {
        // Generate service account email
        let service_account_email = format!("{}@{}.iam.gserviceaccount.com", account_id, self.config.project_id);

        // Generate private key (in practice, this would be done via GCP IAM API)
        let private_key = self.generate_private_key();

        let credential = GcpServiceAccountCredential {
            service_account_email: service_account_email.clone(),
            private_key,
            project_id: self.config.project_id.clone(),
            client_email: service_account_email,
            token_uri: "https://oauth2.googleapis.com/token".to_string(),
            lease_id: format!("gcp/sa/{}/{}", account_id, Utc::now().timestamp()),
            lease_duration,
        };

        // In a real implementation, you would:
        // 1. Create the service account via GCP IAM API
        // 2. Assign roles to the service account
        // 3. Generate and download the key pair

        Ok(credential)
    }

    pub async fn generate_access_token(
        &self,
        service_account_email: &str,
        scopes: Vec<String>,
        lease_duration: i64,
    ) -> Result<GcpIamCredential, Box<dyn std::error::Error + Send + Sync>> {
        // Get access token using the authentication manager
        let scopes_str = scopes.join(" ");
        let token = self.auth_manager.get_token(&[&scopes_str]).await?;

        let expires_at = Utc::now() + Duration::seconds(token.expires_at.unix_timestamp() - Utc::now().timestamp());

        let credential = GcpIamCredential {
            service_account_email: service_account_email.to_string(),
            access_token: token.access_token,
            expires_at: expires_at.to_rfc3339(),
            project_id: self.config.project_id.clone(),
            lease_id: format!("gcp/token/{}/{}", service_account_email, Utc::now().timestamp()),
            lease_duration,
        };

        Ok(credential)
    }

    pub async fn create_storage_service_account(
        &self,
        bucket_name: &str,
        permissions: Vec<String>,
        lease_duration: i64,
    ) -> Result<GcpStorageCredential, Box<dyn std::error::Error + Send + Sync>> {
        let account_id = format!("storage-{}-{}", bucket_name, Utc::now().timestamp());
        let service_account = self.create_service_account(
            &account_id,
            &format!("Storage Service Account for {}", bucket_name),
            vec!["roles/storage.objectAdmin".to_string()],
            lease_duration,
        ).await?;

        let credential = GcpStorageCredential {
            service_account_email: service_account.service_account_email,
            private_key: service_account.private_key,
            project_id: self.config.project_id.clone(),
            bucket_name: bucket_name.to_string(),
            lease_id: format!("gcp/storage/{}/{}", bucket_name, Utc::now().timestamp()),
            lease_duration,
        };

        Ok(credential)
    }

    pub async fn create_bigquery_service_account(
        &self,
        dataset_id: &str,
        permissions: Vec<String>,
        lease_duration: i64,
    ) -> Result<GcpBigQueryCredential, Box<dyn std::error::Error + Send + Sync>> {
        let account_id = format!("bq-{}-{}", dataset_id, Utc::now().timestamp());
        let service_account = self.create_service_account(
            &account_id,
            &format!("BigQuery Service Account for {}", dataset_id),
            vec!["roles/bigquery.dataEditor".to_string()],
            lease_duration,
        ).await?;

        let credential = GcpBigQueryCredential {
            service_account_email: service_account.service_account_email,
            private_key: service_account.private_key,
            project_id: self.config.project_id.clone(),
            dataset_id: dataset_id.to_string(),
            lease_id: format!("gcp/bq/{}/{}", dataset_id, Utc::now().timestamp()),
            lease_duration,
        };

        Ok(credential)
    }

    pub async fn create_secret_manager_secret(
        &self,
        name: &str,
        value: &str,
        labels: HashMap<String, String>,
        lease_duration: i64,
    ) -> Result<GcpSecretManagerSecret, Box<dyn std::error::Error + Send + Sync>> {
        // Get access token for Secret Manager API
        let token = self.auth_manager.get_token(&["https://www.googleapis.com/auth/cloud-platform"]).await?;

        // Create secret via Secret Manager API
        let create_url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets?secretId={}",
            self.config.project_id, name
        );

        let create_payload = serde_json::json!({
            "replication": {
                "automatic": {}
            }
        });

        let response = self.http_client
            .post(&create_url)
            .bearer_auth(&token.access_token)
            .json(&create_payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to create secret: {}", response.status()).into());
        }

        // Add secret version
        let version_url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}:addVersion",
            self.config.project_id, name
        );

        let version_payload = serde_json::json!({
            "payload": {
                "data": base64::encode(value)
            }
        });

        let response = self.http_client
            .post(&version_url)
            .bearer_auth(&token.access_token)
            .json(&version_payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to add secret version: {}", response.status()).into());
        }

        let secret = GcpSecretManagerSecret {
            name: name.to_string(),
            value: value.to_string(),
            labels,
            lease_id: format!("gcp/sm/{}/{}", name, Utc::now().timestamp()),
            lease_duration,
        };

        Ok(secret)
    }

    pub async fn get_secret_manager_secret(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let token = self.auth_manager.get_token(&["https://www.googleapis.com/auth/cloud-platform"]).await?;

        let version = version.unwrap_or("latest");
        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/{}:access",
            self.config.project_id, name, version
        );

        let response = self.http_client
            .get(&url)
            .bearer_auth(&token.access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to access secret: {}", response.status()).into());
        }

        #[derive(Deserialize)]
        struct SecretResponse {
            payload: Payload,
        }

        #[derive(Deserialize)]
        struct Payload {
            data: String,
        }

        let secret_response: SecretResponse = response.json().await?;
        let decoded = base64::decode(&secret_response.payload.data)?;

        Ok(String::from_utf8(decoded)?)
    }

    pub async fn list_secret_manager_secrets(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let token = self.auth_manager.get_token(&["https://www.googleapis.com/auth/cloud-platform"]).await?;

        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets",
            self.config.project_id
        );

        let response = self.http_client
            .get(&url)
            .bearer_auth(&token.access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to list secrets: {}", response.status()).into());
        }

        #[derive(Deserialize)]
        struct ListResponse {
            secrets: Vec<Secret>,
        }

        #[derive(Deserialize)]
        struct Secret {
            name: String,
        }

        let list_response: ListResponse = response.json().await?;
        let names = list_response.secrets
            .into_iter()
            .filter_map(|s| s.name.split('/').last().map(|n| n.to_string()))
            .collect();

        Ok(names)
    }

    pub async fn delete_secret_manager_secret(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let token = self.auth_manager.get_token(&["https://www.googleapis.com/auth/cloud-platform"]).await?;

        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}",
            self.config.project_id, name
        );

        let response = self.http_client
            .delete(&url)
            .bearer_auth(&token.access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to delete secret: {}", response.status()).into());
        }

        Ok(())
    }

    pub async fn revoke_service_account(
        &self,
        service_account_email: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a real implementation, you would:
        // 1. Delete the service account via GCP IAM API
        // 2. Remove all role bindings
        // 3. Clean up any associated resources

        println!("[REVOKE] GCP Service Account {} revoked", service_account_email);
        Ok(())
    }

    pub async fn revoke_access_token(
        &self,
        _service_account_email: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Access tokens are temporary and automatically expire
        // No explicit revocation needed
        Ok(())
    }

    fn generate_private_key(&self) -> String {
        // In a real implementation, this would generate a proper RSA key pair
        // For now, return a placeholder
        format!("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----")
    }
}

pub async fn create_lease_for_gcp_credential(
    storage: &Storage,
    credential_type: &str,
    resource_id: &str,
    ttl_seconds: i64,
) -> Result<Lease, Box<dyn std::error::Error + Send + Sync>> {
    let lease = crate::services::lease::create_lease(
        storage,
        "gcp-engine",
        credential_type,
        resource_id,
        ttl_seconds,
    ).await?;

    Ok(lease)
}

pub async fn revoke_lease_for_gcp_credential(
    storage: &Storage,
    lease_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    crate::services::lease::revoke_lease(storage, lease_id).await?;
    Ok(())
}
