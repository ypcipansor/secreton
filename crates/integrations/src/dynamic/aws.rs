// use crate::utils::config::Config;
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Serialize, Clone, Debug)]
pub struct AwsCredential {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub username: String,
    pub expires_at: String,
    pub role_arn: String,
}

#[derive(Debug, Clone)]
pub struct AwsConfig {
    pub account_id: String,
    pub region: String,
    pub role_prefix: String,
    pub default_duration_seconds: i32,
}

impl Default for AwsConfig {
    fn default() -> Self {
        Self {
            account_id: "123456789012".to_string(), // Should be configured
            region: "us-east-1".to_string(),
            role_prefix: "secreton".to_string(),
            default_duration_seconds: 900, // 15 minutes
        }
    }
}

/// Global registry of revoked AWS credentials
static REVOKED_CREDENTIALS: Lazy<Arc<RwLock<HashSet<String>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashSet::new())));

pub async fn generate_aws_credential(
    role: &str,
    config: Option<&AwsConfig>,
) -> Result<AwsCredential, String> {
    use aws_config::BehaviorVersion;
    use aws_sdk_sts::{Client, config::Region};

    let config: Cow<'_, AwsConfig> = config
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Owned(AwsConfig::default()));

    let aws_config = aws_config::defaults(BehaviorVersion::v2025_08_07())
        .region(Region::new(config.region.clone()))
        .load()
        .await;

    let client = Client::new(&aws_config);

    let role_arn = format!("arn:aws:iam::{}:role/{}", config.account_id, role);

    let assume_role = client
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name(format!("{}-session-{}", config.role_prefix, role))
        .set_duration_seconds(Some(config.default_duration_seconds))
        .send()
        .await
        .map_err(|e| format!("Failed to assume role: {}", e))?;

    let credentials = assume_role.credentials().ok_or("No credentials returned")?;

    let access_key = credentials.access_key_id();
    let secret_key = credentials.secret_access_key();
    let token = credentials.session_token();

    let expiry = credentials
        .expiration()
        .fmt(aws_sdk_sts::primitives::DateTimeFormat::DateTime)
        .unwrap();

    let username = format!("{}_session_{}", role, Utc::now().timestamp());

    Ok(AwsCredential {
        access_key: access_key.to_string(),
        secret_key: secret_key.to_string(),
        session_token: Some(token.to_string()),
        username: username.clone(),
        expires_at: expiry,
        role_arn: role_arn.clone(),
    })
}

pub async fn revoke_aws_credential(username: &str) -> Result<(), String> {
    // Add to revoked credentials set
    let mut revoked = REVOKED_CREDENTIALS.write().await;
    revoked.insert(username.to_string());

    // In a production system, you might also:
    // 1. Store revocation in a database for persistence across restarts
    // 2. Notify any active sessions to terminate
    // 3. Update AWS IAM policies if needed
    // 4. Log the revocation event

    tracing::info!("AWS credential revoked for user: {}", username);
    Ok(())
}

pub async fn is_aws_credential_revoked(username: &str) -> bool {
    let revoked = REVOKED_CREDENTIALS.read().await;
    revoked.contains(username)
}

pub async fn cleanup_expired_aws_credentials() -> usize {
    // In a real implementation, this would clean up expired credentials from the revoked set
    // For now, return 0 as we don't track expiration times in the revoked set
    0
}
