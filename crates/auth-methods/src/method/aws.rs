//! AWS authentication method

use async_trait::async_trait;
use std::collections::HashMap;
use aws_config::BehaviorVersion;
use aws_sdk_sts::{Client as StsClient, config::Credentials};
use aws_sdk_iam::{Client as IamClient};
use aws_sdk_ec2::{Client as Ec2Client};
use crate::model::*;
use crate::error::*;
use crate::service::*;

/// AWS authentication method
pub struct AwsAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    aws_config: Option<AwsClientConfig>,
    sts_client: Option<StsClient>,
    iam_client: Option<IamClient>,
    ec2_client: Option<Ec2Client>,
}

impl AwsAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            aws_config: None,
            sts_client: None,
            iam_client: None,
            ec2_client: None,
        }
    }

    /// Set AWS configuration
    pub fn set_aws_config(&mut self, config: AwsClientConfig) {
        self.aws_config = Some(config);
    }

    /// Initialize AWS clients
    async fn init_clients(&mut self) -> AuthMethodResult<()> {
        if self.sts_client.is_none() {
            let mut config_builder = aws_config::defaults(BehaviorVersion::v2024_03_28());

            if let Some(aws_config) = &self.aws_config {
                if let Some(region) = &aws_config.region {
                    config_builder = config_builder.region(aws_config::Region::new(region.to_string()));
                }
                if let Some(access_key) = &aws_config.access_key_id {
                    let credentials = Credentials::new(
                        access_key,
                        aws_config.secret_access_key.as_deref().unwrap_or(""),
                        aws_config.session_token.as_deref(),
                        None,
                        "secreton",
                    );
                    config_builder = config_builder.credentials_provider(credentials);
                }
            }

            let shared_config = config_builder.load().await;

            self.sts_client = Some(StsClient::new(&shared_config));
            self.iam_client = Some(IamClient::new(&shared_config));
            self.ec2_client = Some(Ec2Client::new(&shared_config));
        }
        Ok(())
    }

    /// Validate AWS credentials
    async fn validate_credentials(&self, access_key: &str, secret_key: &str, session_token: Option<&str>) -> AuthMethodResult<AwsIdentity> {
        self.init_clients().await?;

        let sts_client = self.sts_client.as_ref()
            .ok_or(AuthMethodError::ConfigurationError("STS client not initialized".to_string()))?;

        // Create temporary credentials for validation
        let credentials = Credentials::new(
            access_key,
            secret_key,
            session_token,
            None,
            "secreton-validation",
        );

        // Try to get caller identity
        let identity = sts_client
            .get_caller_identity()
            .credentials_provider(credentials)
            .send()
            .await
            .map_err(|e| AuthMethodError::AwsError(format!("Failed to validate credentials: {}", e)))?;

        let account = identity.account()
            .ok_or(AuthMethodError::AwsError("No account in identity".to_string()))?;
        let user_id = identity.user_id()
            .ok_or(AuthMethodError::AwsError("No user ID in identity".to_string()))?;
        let arn = identity.arn()
            .ok_or(AuthMethodError::AwsError("No ARN in identity".to_string()))?;

        Ok(AwsIdentity {
            account: account.to_string(),
            id: user_id.to_string(),
            arn: arn.to_string(),
            username: extract_username_from_arn(arn),
            roles: vec![],
            policies: vec![],
        })
    }

    /// Get IAM user information
    async fn get_iam_user_info(&self, username: &str) -> AuthMethodResult<AwsUserInfo> {
        let iam_client = self.iam_client.as_ref()
            .ok_or(AuthMethodError::ConfigurationError("IAM client not initialized".to_string()))?;

        let user = iam_client
            .get_user()
            .user_name(username)
            .send()
            .await
            .map_err(|e| AuthMethodError::AwsError(format!("Failed to get IAM user: {}", e)))?;

        let user_detail = user.user();
        let arn = user_detail.arn().unwrap_or("");
        let user_id = user_detail.user_id().unwrap_or("");
        let create_date = user_detail.create_date().map(|d| d.to_string()).unwrap_or_default();

        Ok(AwsUserInfo {
            username: username.to_string(),
            id: user_id.to_string(),
            arn: arn.to_string(),
            create_date,
            groups: vec![],
            policies: vec![],
        })
    }

    /// Get EC2 instance information
    async fn get_ec2_instance_info(&self, instance_id: &str) -> AuthMethodResult<AwsInstanceInfo> {
        let ec2_client = self.ec2_client.as_ref()
            .ok_or(AuthMethodError::ConfigurationError("EC2 client not initialized".to_string()))?;

        let instances = ec2_client
            .describe_instances()
            .instance_ids(instance_id)
            .send()
            .await
            .map_err(|e| AuthMethodError::AwsError(format!("Failed to get EC2 instance: {}", e)))?;

        if let Some(reservation) = instances.reservations().first() {
            if let Some(instance) = reservation.instances().first() {
                let instance_type = instance.instance_type().map(|it| it.as_str()).unwrap_or("unknown");
                let availability_zone = instance.placement().and_then(|p| p.availability_zone()).unwrap_or("unknown");
                let tags = instance.tags().iter()
                    .map(|tag| (tag.key().unwrap_or("").to_string(), tag.value().unwrap_or("").to_string()))
                    .collect();

                Ok(AwsInstanceInfo {
                    instance_id: instance_id.to_string(),
                    instance_type: instance_type.to_string(),
                    availability_zone: availability_zone.to_string(),
                    tags,
                })
            } else {
                Err(AuthMethodError::AwsError("Instance not found".to_string()))
            }
        } else {
            Err(AuthMethodError::AwsError("Instance not found".to_string()))
        }
    }
}

#[async_trait]
impl AuthMethodImpl for AwsAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::Aws
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.clone());

        // Parse AWS configuration from config
        let aws_config = AwsClientConfig {
            region: config.config.get("region").and_then(|v| v.as_str()).map(|s| s.to_string()),
            access_key_id: config.config.get("access_key_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
            secret_access_key: config.config.get("secret_access_key").and_then(|v| v.as_str()).map(|s| s.to_string()),
            session_token: config.config.get("session_token").and_then(|v| v.as_str()).map(|s| s.to_string()),
            iam_role_arn: config.config.get("iam_role_arn").and_then(|v| v.as_str()).map(|s| s.to_string()),
            ec2_instance_profile: config.config.get("ec2_instance_profile")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        };
        self.set_aws_config(aws_config);

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        if !self.is_enabled() {
            return Err(AuthMethodError::MethodDisabled);
        }

        match credentials {
            AuthCredentials::Aws { access_key, secret_key, session_token } => {
                let aws_identity = self.validate_credentials(access_key, secret_key, session_token.as_deref()).await?;

                let user_info = UserInfo {
                    username: aws_identity.username.to_string(),
                    id: Uuid::new_v4(), // Generate UUID since AWS doesn't provide UUID
                    groups: aws_identity.roles.clone(),
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("aws_account".to_string(), aws_identity.account.to_string());
                        meta.insert("aws_arn".to_string(), aws_identity.arn.to_string());
                        meta
                    },
                    email: None,
                    display_name: Some(aws_identity.username.to_string()),
                    created_at: Utc::now(),
                    last_login: Some(Utc::now()),
                };

                Ok(AuthResult {
                    authenticated: true,
                    user_info: Some(user_info),
                    token: None,
                    mfa_required: false,
                    policies: aws_identity.policies.clone(),
                    lease_duration: None,
                    renewable: Some(true),
                    metadata: HashMap::new(),
                    accessor: None,
                    mfa_methods: Vec::new(),
                })
            }
            _ => Err(AuthMethodError::InvalidCredentials("Invalid AWS credentials".to_string())),
        }
    }

    async fn validate_token(&self, _token: &str) -> AuthMethodResult<UserInfo> {
        Err(AuthMethodError::MethodNotSupported)
    }

    async fn revoke_token(&self, _token: &str) -> AuthMethodResult<()> {
        Err(AuthMethodError::MethodNotSupported)
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}

/// AWS client configuration (for SDK setup)
#[derive(Clone, Debug)]
pub struct AwsClientConfig {
    pub region: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub iam_role_arn: Option<String>,
    pub ec2_instance_profile: bool,
}

/// AWS identity information
#[derive(Clone, Debug)]
pub struct AwsIdentity {
    pub account: String,
    pub id: String,
    pub arn: String,
    pub username: String,
    pub roles: Vec<String>,
    pub policies: Vec<String>,
}

/// AWS user information
#[derive(Clone, Debug)]
pub struct AwsUserInfo {
    pub username: String,
    pub id: String,
    pub arn: String,
    pub create_date: String,
    pub groups: Vec<String>,
    pub policies: Vec<String>,
}

/// AWS EC2 instance information
#[derive(Clone, Debug)]
pub struct AwsInstanceInfo {
    pub instance_id: String,
    pub instance_type: String,
    pub availability_zone: String,
    pub tags: HashMap<String, String>,
}

/// Extract username from ARN
fn extract_username_from_arn(arn: &str) -> String {
    // ARN format: arn:aws:iam::123456789012:user/username
    if let Some(user_part) = arn.split(':').nth(5) {
        if let Some(username) = user_part.split('/').nth(1) {
            username.to_string()
        } else {
            user_part.to_string()
        }
    } else {
        "unknown".to_string()
    }
}