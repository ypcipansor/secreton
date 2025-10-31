//! AWS backend for secret management

use crate::error::*;
use serde_json::Value;
use std::collections::HashMap;

/// AWS backend for generating temporary credentials
pub struct AwsBackend {
    _access_key: String,
    _secret_key: String,
    region: String,
}

impl AwsBackend {
    pub fn new(access_key: String, secret_key: String, region: String) -> Self {
        Self {
            _access_key: access_key,
            _secret_key: secret_key,
            region,
        }
    }

    /// Generate temporary AWS credentials
    pub async fn generate_credentials(
        &self,
        role_arn: Option<&str>,
        ttl_seconds: u32,
    ) -> SecretResult<HashMap<String, Value>> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(self.region.clone()))
            .load()
            .await;

        let sts_client = aws_sdk_sts::Client::new(&config);

        let mut credentials_result = HashMap::new();

        if let Some(role_arn) = role_arn {
            // Use AssumeRole for cross-account or role-based access
            let assume_role_request = sts_client
                .assume_role()
                .role_arn(role_arn)
                .role_session_name("secreton-session")
                .duration_seconds(ttl_seconds as i32);

            match assume_role_request.send().await {
                Ok(response) => {
                    if let Some(credentials) = response.credentials {
                        let access_key = credentials.access_key_id().to_string();
                        let secret_key = credentials.secret_access_key().to_string();
                        let session_token = credentials.session_token().to_string();
                        credentials_result
                            .insert("access_key".to_string(), Value::String(access_key));
                        credentials_result
                            .insert("secret_key".to_string(), Value::String(secret_key));
                        credentials_result
                            .insert("session_token".to_string(), Value::String(session_token));
                        credentials_result
                            .insert("role_arn".to_string(), Value::String(role_arn.to_string()));
                        credentials_result
                            .insert("ttl".to_string(), Value::Number(ttl_seconds.into()));
                        credentials_result.insert("assumed_role".to_string(), Value::Bool(true));
                    } else {
                        return Err(SecretError::InvalidConfiguration(
                            "No credentials returned from AssumeRole".to_string(),
                        ));
                    }
                }
                Err(e) => {
                    return Err(SecretError::InvalidConfiguration(format!(
                        "Failed to assume role: {}",
                        e
                    )));
                }
            }
        } else {
            // Use GetSessionToken for temporary credentials with current permissions
            let session_token_request = sts_client
                .get_session_token()
                .duration_seconds(ttl_seconds as i32);

            match session_token_request.send().await {
                Ok(response) => {
                    if let Some(credentials) = response.credentials {
                        let access_key = credentials.access_key_id().to_string();
                        let secret_key = credentials.secret_access_key().to_string();
                        let session_token = credentials.session_token().to_string();
                        credentials_result
                            .insert("access_key".to_string(), Value::String(access_key));
                        credentials_result
                            .insert("secret_key".to_string(), Value::String(secret_key));
                        credentials_result
                            .insert("session_token".to_string(), Value::String(session_token));
                        credentials_result
                            .insert("ttl".to_string(), Value::Number(ttl_seconds.into()));
                        credentials_result.insert("assumed_role".to_string(), Value::Bool(false));
                    } else {
                        return Err(SecretError::InvalidConfiguration(
                            "No credentials returned from GetSessionToken".to_string(),
                        ));
                    }
                }
                Err(e) => {
                    return Err(SecretError::InvalidConfiguration(format!(
                        "Failed to get session token: {}",
                        e
                    )));
                }
            }
        }

        Ok(credentials_result)
    }

    /// Test AWS connectivity
    pub async fn test_connection(&self) -> SecretResult<()> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(self.region.clone()))
            .load()
            .await;

        let sts_client = aws_sdk_sts::Client::new(&config);

        // Test connectivity by calling GetCallerIdentity
        match sts_client.get_caller_identity().send().await {
            Ok(identity) => {
                // Verify we can get the account information
                if identity.account().is_some() && identity.user_id().is_some() {
                    Ok(())
                } else {
                    Err(SecretError::InvalidConfiguration(
                        "AWS credentials are invalid or insufficient permissions".to_string(),
                    ))
                }
            }
            Err(e) => Err(SecretError::InvalidConfiguration(format!(
                "AWS connectivity test failed: {}",
                e
            ))),
        }
    }
}
