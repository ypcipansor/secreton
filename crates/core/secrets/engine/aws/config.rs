use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for AWS secrets engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    /// AWS region to operate in
    pub region: String,

    /// Access key ID for AWS API access
    pub access_key: Option<String>,

    /// Secret access key for AWS API access
    pub secret_key: Option<String>,

    /// Maximum TTL for generated credentials
    pub max_ttl: u64,

    /// Default TTL for generated credentials (in seconds)
    pub default_ttl: u64,

    /// IAM path prefix for created users/roles
    pub iam_path_prefix: String,

    /// Tags to apply to created resources
    pub default_tags: HashMap<String, String>,

    /// Whether to use instance profile credentials
    pub use_instance_profile: bool,

    /// ARN of role to assume for operations
    pub assume_role_arn: Option<String>,

    /// External ID for role assumption
    pub external_id: Option<String>,
}

impl Default for AwsConfig {
    fn default() -> Self {
        Self {
            region: "us-east-1".to_string(),
            access_key: None,
            secret_key: None,
            max_ttl: 86400 * 30, // 30 days
            default_ttl: 3600,   // 1 hour
            iam_path_prefix: "/secreton/".to_string(),
            default_tags: HashMap::new(),
            use_instance_profile: true,
            assume_role_arn: None,
            external_id: None,
        }
    }
}

/// Role configuration for AWS credential generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsRoleConfig {
    /// Name of the role
    pub name: String,

    /// Type of credential to generate (user, role, assumed_role, federation_token)
    pub credential_type: AwsCredentialType,

    /// IAM policy document to attach (JSON string)
    pub policy_document: Option<String>,

    /// ARNs of managed policies to attach
    pub policy_arns: Vec<String>,

    /// TTL for generated credentials
    pub ttl: Option<u64>,

    /// Role ARN to assume (for assumed_role type)
    pub role_arn: Option<String>,

    /// Session name for assumed role
    pub session_name: Option<String>,

    /// External ID for role assumption
    pub external_id: Option<String>,

    /// Tags to apply to generated resources
    pub tags: HashMap<String, String>,
}

/// Types of AWS credentials that can be generated
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum AwsCredentialType {
    /// Create IAM user with access keys
    #[default]
    User,

    /// Create IAM role
    Role,

    /// Assume an existing role
    AssumedRole,

    /// Generate federation token
    FederationToken,

    /// Generate STS session token
    SessionToken,
}

/// AWS credential response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCredentials {
    /// Access key ID
    pub access_key_id: String,

    /// Secret access key
    pub secret_access_key: String,

    /// Session token (for temporary credentials)
    pub session_token: Option<String>,

    /// Expiration time (for temporary credentials)
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,

    /// ARN of the created/assumed identity
    pub arn: String,

    /// User ID of the identity
    pub user_id: String,

    /// Type of credential generated
    pub credential_type: AwsCredentialType,

    /// Lease ID for revocation
    pub lease_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_config_default() {
        let config = AwsConfig::default();
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.max_ttl, 86400 * 30);
        assert_eq!(config.default_ttl, 3600);
        assert_eq!(config.iam_path_prefix, "/secreton/");
        assert!(config.use_instance_profile);
    }

    #[test]
    fn test_aws_role_config_serialization() {
        let role_config = AwsRoleConfig {
            name: "test-role".to_string(),
            credential_type: AwsCredentialType::User,
            policy_document: Some(r#"{"Version":"2012-10-17","Statement":[]}"#.to_string()),
            policy_arns: vec!["arn:aws:iam::aws:policy/ReadOnlyAccess".to_string()],
            ttl: Some(3600),
            role_arn: None,
            session_name: None,
            external_id: None,
            tags: HashMap::new(),
        };

        let serialized = serde_json::to_string(&role_config).unwrap();
        let deserialized: AwsRoleConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(role_config.name, deserialized.name);
        assert_eq!(role_config.ttl, deserialized.ttl);
    }
}
