use anyhow::{Context, Result};
use aws_sdk_iam::Client as IamClient;
use serde_json::json;
use std::collections::HashMap;
use tracing::{info, warn};

use super::config::{AwsCredentialType, AwsCredentials, AwsRoleConfig};

/// IAM operations handler for AWS secrets engine
pub struct IamHandler {
    client: IamClient,
    path_prefix: String,
    default_tags: HashMap<String, String>,
}

impl IamHandler {
    pub fn new(
        client: IamClient,
        path_prefix: String,
        default_tags: HashMap<String, String>,
    ) -> Self {
        Self {
            client,
            path_prefix,
            default_tags,
        }
    }

    /// Create IAM user with access keys
    pub async fn create_user_credentials(
        &self,
        role_config: &AwsRoleConfig,
        lease_id: &str,
    ) -> Result<AwsCredentials> {
        let username = format!("secreton-{}-{}", role_config.name, &lease_id[..8]);

        info!("Creating IAM user: {}", username);

        // Create user
        let user_path = format!("{}{}/", self.path_prefix, role_config.name);
        self.client
            .create_user()
            .user_name(&username)
            .path(&user_path)
            .send()
            .await
            .context("Failed to create IAM user")?;

        // Attach inline policy if provided
        if let Some(policy_doc) = &role_config.policy_document {
            let policy_name = format!("secreton-policy-{}", &lease_id[..8]);
            self.client
                .put_user_policy()
                .user_name(&username)
                .policy_name(&policy_name)
                .policy_document(policy_doc)
                .send()
                .await
                .context("Failed to attach inline policy to user")?;
        }

        // Attach managed policies
        for policy_arn in &role_config.policy_arns {
            self.client
                .attach_user_policy()
                .user_name(&username)
                .policy_arn(policy_arn)
                .send()
                .await
                .with_context(|| format!("Failed to attach managed policy: {}", policy_arn))?;
        }

        // Create access key
        let access_key_response = self
            .client
            .create_access_key()
            .user_name(&username)
            .send()
            .await
            .context("Failed to create access key")?;

        let access_key = access_key_response
            .access_key()
            .context("No access key in response")?;

        // Get user info for ARN
        let user_response = self
            .client
            .get_user()
            .user_name(&username)
            .send()
            .await
            .context("Failed to get user info")?;

        let user = user_response.user().context("No user in response")?;

        Ok(AwsCredentials {
            access_key_id: access_key.access_key_id().to_string(),
            secret_access_key: access_key.secret_access_key().to_string(),
            session_token: None,
            expiration: None,
            arn: user.arn().to_string(),
            user_id: user.user_id().to_string(),
            credential_type: AwsCredentialType::User,
            lease_id: lease_id.to_string(),
        })
    }

    /// Create IAM role
    pub async fn create_role_credentials(
        &self,
        role_config: &AwsRoleConfig,
        lease_id: &str,
    ) -> Result<AwsCredentials> {
        let role_name = format!("secreton-{}-{}", role_config.name, &lease_id[..8]);

        info!("Creating IAM role: {}", role_name);

        // Default assume role policy document (can be assumed by current account)
        let assume_role_policy = json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        });

        // Create role
        let role_path = format!("{}{}/", self.path_prefix, role_config.name);
        let create_role_response = self
            .client
            .create_role()
            .role_name(&role_name)
            .path(&role_path)
            .assume_role_policy_document(assume_role_policy.to_string())
            .send()
            .await
            .context("Failed to create IAM role")?;

        let role = create_role_response.role().context("No role in response")?;

        // Attach inline policy if provided
        if let Some(policy_doc) = &role_config.policy_document {
            let policy_name = format!("secreton-policy-{}", &lease_id[..8]);
            self.client
                .put_role_policy()
                .role_name(&role_name)
                .policy_name(&policy_name)
                .policy_document(policy_doc)
                .send()
                .await
                .context("Failed to attach inline policy to role")?;
        }

        // Attach managed policies
        for policy_arn in &role_config.policy_arns {
            self.client
                .attach_role_policy()
                .role_name(&role_name)
                .policy_arn(policy_arn)
                .send()
                .await
                .with_context(|| format!("Failed to attach managed policy: {}", policy_arn))?;
        }

        // Return role info (no access keys for roles directly)
        Ok(AwsCredentials {
            access_key_id: "".to_string(), // Roles don't have static access keys
            secret_access_key: "".to_string(),
            session_token: None,
            expiration: None,
            arn: role.arn().to_string(),
            user_id: role.role_id().to_string(),
            credential_type: AwsCredentialType::Role,
            lease_id: lease_id.to_string(),
        })
    }

    /// Delete IAM user and all associated resources
    pub async fn delete_user(&self, username: &str) -> Result<()> {
        info!("Deleting IAM user: {}", username);

        // Delete access keys
        let list_keys_response = self
            .client
            .list_access_keys()
            .user_name(username)
            .send()
            .await;

        if let Ok(response) = list_keys_response {
            for access_key in response.access_key_metadata() {
                if let Some(access_key_id) = access_key.access_key_id() {
                    if let Err(e) = self
                        .client
                        .delete_access_key()
                        .user_name(username)
                        .access_key_id(access_key_id)
                        .send()
                        .await
                    {
                        warn!("Failed to delete access key {}: {}", access_key_id, e);
                    }
                }
            }
        }

        // Detach managed policies
        let list_policies_response = self
            .client
            .list_attached_user_policies()
            .user_name(username)
            .send()
            .await;

        if let Ok(response) = list_policies_response {
            for policy in response.attached_policies() {
                if let Err(e) = self
                    .client
                    .detach_user_policy()
                    .user_name(username)
                    .policy_arn(policy.policy_arn().unwrap_or(""))
                    .send()
                    .await
                {
                    warn!(
                        "Failed to detach policy {}: {}",
                        policy.policy_name().unwrap_or(""),
                        e
                    );
                }
            }
        }

        // Delete inline policies
        let list_inline_policies_response = self
            .client
            .list_user_policies()
            .user_name(username)
            .send()
            .await;

        if let Ok(response) = list_inline_policies_response {
            for policy_name in response.policy_names() {
                if let Err(e) = self
                    .client
                    .delete_user_policy()
                    .user_name(username)
                    .policy_name(policy_name)
                    .send()
                    .await
                {
                    warn!("Failed to delete inline policy {}: {}", policy_name, e);
                }
            }
        }

        // Delete user
        self.client
            .delete_user()
            .user_name(username)
            .send()
            .await
            .context("Failed to delete IAM user")?;

        info!("Successfully deleted IAM user: {}", username);
        Ok(())
    }

    /// Delete IAM role and all associated resources
    pub async fn delete_role(&self, role_name: &str) -> Result<()> {
        info!("Deleting IAM role: {}", role_name);

        // Detach managed policies
        let list_policies_response = self
            .client
            .list_attached_role_policies()
            .role_name(role_name)
            .send()
            .await;

        if let Ok(response) = list_policies_response {
            for policy in response.attached_policies() {
                if let Err(e) = self
                    .client
                    .detach_role_policy()
                    .role_name(role_name)
                    .policy_arn(policy.policy_arn().unwrap_or(""))
                    .send()
                    .await
                {
                    warn!(
                        "Failed to detach policy {}: {}",
                        policy.policy_name().unwrap_or(""),
                        e
                    );
                }
            }
        }

        // Delete inline policies
        let list_inline_policies_response = self
            .client
            .list_role_policies()
            .role_name(role_name)
            .send()
            .await;

        if let Ok(response) = list_inline_policies_response {
            for policy_name in response.policy_names() {
                if let Err(e) = self
                    .client
                    .delete_role_policy()
                    .role_name(role_name)
                    .policy_name(policy_name)
                    .send()
                    .await
                {
                    warn!("Failed to delete inline policy {}: {}", policy_name, e);
                }
            }
        }

        // Delete role
        self.client
            .delete_role()
            .role_name(role_name)
            .send()
            .await
            .context("Failed to delete IAM role")?;

        info!("Successfully deleted IAM role: {}", role_name);
        Ok(())
    }

    /// Extract username from ARN for cleanup
    pub fn extract_username_from_arn(arn: &str) -> Option<String> {
        // ARN format: arn:aws:iam::account:user/path/username
        if let Some(user_part) = arn.strip_prefix("arn:aws:iam::") {
            if let Some(username_part) = user_part.split_once(":user/") {
                return Some(username_part.1.split('/').next_back()?.to_string());
            }
        }
        None
    }

    /// Extract role name from ARN for cleanup
    pub fn extract_role_name_from_arn(arn: &str) -> Option<String> {
        // ARN format: arn:aws:iam::account:role/path/rolename
        if let Some(role_part) = arn.strip_prefix("arn:aws:iam::") {
            if let Some(role_name_part) = role_part.split_once(":role/") {
                return Some(role_name_part.1.split('/').next_back()?.to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_username_from_arn() {
        let arn = "arn:aws:iam::123456789012:user/secreton/test/secreton-test-12345678";
        let username = IamHandler::extract_username_from_arn(arn);
        assert_eq!(username, Some("secreton-test-12345678".to_string()));
    }

    #[test]
    fn test_extract_role_name_from_arn() {
        let arn = "arn:aws:iam::123456789012:role/secreton/test/secreton-test-12345678";
        let role_name = IamHandler::extract_role_name_from_arn(arn);
        assert_eq!(role_name, Some("secreton-test-12345678".to_string()));
    }

    #[test]
    fn test_invalid_arn() {
        let arn = "invalid-arn";
        let username = IamHandler::extract_username_from_arn(arn);
        assert_eq!(username, None);
    }
}
