use anyhow::{Context, Result};
use aws_sdk_sts::Client as StsClient;
use chrono::Utc;
use tracing::info;

use super::config::{AwsCredentialType, AwsCredentials, AwsRoleConfig};

/// Helper function to convert AWS SDK DateTime to chrono DateTime
fn convert_aws_datetime(
    aws_datetime: Option<&aws_sdk_sts::primitives::DateTime>,
) -> Option<chrono::DateTime<Utc>> {
    aws_datetime.and_then(|dt| chrono::DateTime::from_timestamp(dt.secs(), dt.subsec_nanos()))
}

/// STS operations handler for AWS secrets engine
pub struct StsHandler {
    client: StsClient,
}

impl StsHandler {
    pub fn new(client: StsClient) -> Self {
        Self { client }
    }

    /// Assume an existing IAM role
    pub async fn assume_role(
        &self,
        role_config: &AwsRoleConfig,
        lease_id: &str,
    ) -> Result<AwsCredentials> {
        let role_arn = role_config
            .role_arn
            .as_ref()
            .context("Role ARN is required for assumed role credentials")?;

        let session_name = role_config
            .session_name.clone()
            .unwrap_or_else(|| format!("secreton-{}-{}", role_config.name, &lease_id[..8]));

        info!("Assuming role: {} with session: {}", role_arn, session_name);

        let mut assume_role_request = self
            .client
            .assume_role()
            .role_arn(role_arn)
            .role_session_name(&session_name);

        // Add external ID if provided
        if let Some(external_id) = &role_config.external_id {
            assume_role_request = assume_role_request.external_id(external_id);
        }

        // Add duration if TTL is specified
        if let Some(ttl) = role_config.ttl {
            let duration_seconds = std::cmp::min(ttl as i32, 43200); // Max 12 hours
            assume_role_request = assume_role_request.duration_seconds(duration_seconds);
        }

        // Add session policy if provided
        if let Some(policy_doc) = &role_config.policy_document {
            assume_role_request = assume_role_request.policy(policy_doc);
        }

        let response = assume_role_request
            .send()
            .await
            .context("Failed to assume role")?;

        let credentials = response
            .credentials()
            .context("No credentials in assume role response")?;

        let assumed_role_user = response
            .assumed_role_user()
            .context("No assumed role user in response")?;

        // Convert expiration to chrono DateTime
        let expiration = convert_aws_datetime(Some(credentials.expiration()));

        Ok(AwsCredentials {
            access_key_id: credentials.access_key_id().to_string(),
            secret_access_key: credentials.secret_access_key().to_string(),
            session_token: Some(credentials.session_token().to_string()),
            expiration,
            arn: assumed_role_user.arn().to_string(),
            user_id: assumed_role_user.assumed_role_id().to_string(),
            credential_type: AwsCredentialType::AssumedRole,
            lease_id: lease_id.to_string(),
        })
    }

    /// Generate federation token
    pub async fn get_federation_token(
        &self,
        role_config: &AwsRoleConfig,
        lease_id: &str,
    ) -> Result<AwsCredentials> {
        let name = format!("secreton-{}-{}", role_config.name, &lease_id[..8]);

        info!("Getting federation token: {}", name);

        let mut federation_request = self.client.get_federation_token().name(&name);

        // Add duration if TTL is specified
        if let Some(ttl) = role_config.ttl {
            let duration_seconds = std::cmp::min(ttl as i32, 129600); // Max 36 hours
            federation_request = federation_request.duration_seconds(duration_seconds);
        }

        // Add policy if provided
        if let Some(policy_doc) = &role_config.policy_document {
            federation_request = federation_request.policy(policy_doc);
        }

        let response = federation_request
            .send()
            .await
            .context("Failed to get federation token")?;

        let credentials = response
            .credentials()
            .context("No credentials in federation token response")?;

        let federated_user = response
            .federated_user()
            .context("No federated user in response")?;

        // Convert expiration to chrono DateTime
        let expiration = convert_aws_datetime(Some(credentials.expiration()));

        Ok(AwsCredentials {
            access_key_id: credentials.access_key_id().to_string(),
            secret_access_key: credentials.secret_access_key().to_string(),
            session_token: Some(credentials.session_token().to_string()),
            expiration,
            arn: federated_user.arn().to_string(),
            user_id: federated_user.federated_user_id().to_string(),
            credential_type: AwsCredentialType::FederationToken,
            lease_id: lease_id.to_string(),
        })
    }

    /// Generate session token (for MFA scenarios)
    pub async fn get_session_token(
        &self,
        role_config: &AwsRoleConfig,
        lease_id: &str,
        serial_number: Option<&str>,
        token_code: Option<&str>,
    ) -> Result<AwsCredentials> {
        info!("Getting session token");

        let mut session_request = self.client.get_session_token();

        // Add duration if TTL is specified
        if let Some(ttl) = role_config.ttl {
            let duration_seconds = std::cmp::min(ttl as i32, 129600); // Max 36 hours
            session_request = session_request.duration_seconds(duration_seconds);
        }

        // Add MFA if provided
        if let (Some(serial), Some(token)) = (serial_number, token_code) {
            session_request = session_request.serial_number(serial).token_code(token);
        }

        let response = session_request
            .send()
            .await
            .context("Failed to get session token")?;

        let credentials = response
            .credentials()
            .context("No credentials in session token response")?;

        // Convert expiration to chrono DateTime
        let expiration = convert_aws_datetime(Some(credentials.expiration()));

        // Get caller identity to populate ARN and user ID
        let caller_identity = self
            .client
            .get_caller_identity()
            .send()
            .await
            .context("Failed to get caller identity")?;

        Ok(AwsCredentials {
            access_key_id: credentials.access_key_id().to_string(),
            secret_access_key: credentials.secret_access_key().to_string(),
            session_token: Some(credentials.session_token().to_string()),
            expiration,
            arn: caller_identity.arn().unwrap_or("").to_string(),
            user_id: caller_identity.user_id().unwrap_or("").to_string(),
            credential_type: AwsCredentialType::SessionToken,
            lease_id: lease_id.to_string(),
        })
    }

    /// Get caller identity (useful for debugging and validation)
    pub async fn get_caller_identity(&self) -> Result<(String, String, String)> {
        let response = self
            .client
            .get_caller_identity()
            .send()
            .await
            .context("Failed to get caller identity")?;

        Ok((
            response.user_id().unwrap_or("").to_string(),
            response.account().unwrap_or("").to_string(),
            response.arn().unwrap_or("").to_string(),
        ))
    }

    /// Validate assumed role ARN format
    pub fn validate_role_arn(arn: &str) -> Result<()> {
        if !arn.starts_with("arn:aws:iam::") || !arn.contains(":role/") {
            return Err(anyhow::anyhow!("Invalid role ARN format: {}", arn));
        }
        Ok(())
    }

    /// Calculate appropriate TTL based on credential type
    pub fn calculate_ttl(credential_type: &AwsCredentialType, requested_ttl: Option<u64>) -> u64 {
        let max_ttl = match credential_type {
            AwsCredentialType::AssumedRole => 43200,      // 12 hours
            AwsCredentialType::FederationToken => 129600, // 36 hours
            AwsCredentialType::SessionToken => 129600,    // 36 hours
            AwsCredentialType::User => u64::MAX,          // No limit for permanent users
            AwsCredentialType::Role => u64::MAX,          // No limit for permanent roles
        };

        requested_ttl
            .map(|ttl| std::cmp::min(ttl, max_ttl))
            .unwrap_or(3600) // Default 1 hour
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_role_arn_valid() {
        let arn = "arn:aws:iam::123456789012:role/test-role";
        assert!(StsHandler::validate_role_arn(arn).is_ok());
    }

    #[test]
    fn test_validate_role_arn_invalid() {
        let arn = "arn:aws:iam::123456789012:user/test-user";
        assert!(StsHandler::validate_role_arn(arn).is_err());

        let arn = "invalid-arn";
        assert!(StsHandler::validate_role_arn(arn).is_err());
    }

    #[test]
    fn test_calculate_ttl() {
        // Test assumed role limits
        let ttl = StsHandler::calculate_ttl(&AwsCredentialType::AssumedRole, Some(50000));
        assert_eq!(ttl, 43200); // Should be capped at 12 hours

        // Test federation token limits
        let ttl = StsHandler::calculate_ttl(&AwsCredentialType::FederationToken, Some(200000));
        assert_eq!(ttl, 129600); // Should be capped at 36 hours

        // Test user type (no limit)
        let ttl = StsHandler::calculate_ttl(&AwsCredentialType::User, Some(200000));
        assert_eq!(ttl, 200000); // Should not be capped

        // Test default TTL
        let ttl = StsHandler::calculate_ttl(&AwsCredentialType::AssumedRole, None);
        assert_eq!(ttl, 3600); // Should default to 1 hour
    }
}
