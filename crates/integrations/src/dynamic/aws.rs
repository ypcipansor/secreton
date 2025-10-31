// use crate::utils::config::Config;
use chrono::{Duration, Utc};
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct AwsCredential {
    pub access_key: String,
    pub secret_key: String,
    pub username: String,
    pub expires_at: String,
}

pub async fn generate_aws_credential(role: &str) -> Result<AwsCredential, String> {
    // Dummy: generate random access_key/secret_key, expiry
    // (Bisa dikembangkan: create IAM user, attach policy, generate access key)
    let username = format!("{}_{}", role, Utc::now().timestamp());
    let access_key = format!("AKIA{}", username);
    let secret_key = format!("SK{}", username);
    let expires_at = (Utc::now() + Duration::minutes(30)).to_rfc3339();
    Ok(AwsCredential {
        access_key,
        secret_key,
        username,
        expires_at,
    })
}

pub async fn revoke_aws_credential(username: &str) {
    // Dummy: print, bisa dikembangkan ke AWS SDK
    println!("[REVOKE] AWS user {} revoked", username);
}
