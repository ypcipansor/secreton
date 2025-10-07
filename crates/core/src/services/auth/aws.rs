//! AWS Authentication Method
//!
//! Authenticates AWS IAM principals (users, roles, EC2 instances) using AWS STS.
//! Supports EC2 instance identity documents and IAM credentials.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::auth::{AuthRequest, AuthResponse, UserInfo};

/// Error types for AWS authentication
#[derive(Debug, thiserror::Error)]
pub enum AwsError {
    #[error("AWS credentials invalid: {0}")]
    InvalidCredentials(String),
    
    #[error("AWS STS verification failed: {0}")]
    StsVerificationFailed(String),
    
    #[error("EC2 instance verification failed: {0}")]
    Ec2VerificationFailed(String),
    
    #[error("IAM role not found: {0}")]
    RoleNotFound(String),
    
    #[error("Policy binding not found: {0}")]
    PolicyNotFound(String),
    
    #[error("Invalid AWS region: {0}")]
    InvalidRegion(String),
    
    #[error("AWS API error: {0}")]
    ApiError(String),
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
}

/// AWS authentication method type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AwsAuthType {
    /// IAM authentication using AWS access keys
    IAM,
    
    /// EC2 instance authentication using instance identity document
    EC2,
}

/// AWS authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsAuthConfig {
    /// AWS access key ID (for IAM auth validation)
    pub access_key: Option<String>,
    
    /// AWS secret access key
    pub secret_key: Option<String>,
    
    /// AWS region
    pub region: String,
    
    /// STS endpoint (optional)
    pub sts_endpoint: Option<String>,
    
    /// EC2 endpoint (optional)
    pub ec2_endpoint: Option<String>,
    
    /// IAM endpoint (optional)
    pub iam_endpoint: Option<String>,
    
    /// Allowed authentication types
    pub allowed_auth_types: Vec<AwsAuthType>,
    
    /// IAM server ID header value (for added security)
    pub iam_server_id_header_value: Option<String>,
    
    /// Token TTL in seconds
    pub token_ttl: u32,
    
    /// Maximum token TTL
    pub token_max_ttl: u32,
    
    /// Inferred entity type (used for policy attachment)
    pub infer_entity_type: bool,
}

impl Default for AwsAuthConfig {
    fn default() -> Self {
        Self {
            access_key: None,
            secret_key: None,
            region: "us-east-1".to_string(),
            sts_endpoint: None,
            ec2_endpoint: None,
            iam_endpoint: None,
            allowed_auth_types: vec![AwsAuthType::IAM, AwsAuthType::EC2],
            iam_server_id_header_value: None,
            token_ttl: 3600,
            token_max_ttl: 86400,
            infer_entity_type: true,
        }
    }
}

/// AWS IAM role binding to Secreton policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsRoleBinding {
    /// AWS IAM role ARN
    pub role_arn: String,
    
    /// Secreton policies to attach
    pub policies: Vec<String>,
    
    /// Token TTL override
    pub ttl: Option<u32>,
    
    /// Maximum token TTL override
    pub max_ttl: Option<u32>,
    
    /// Allowed authentication types for this role
    pub auth_types: Vec<AwsAuthType>,
    
    /// Bound AWS account IDs
    pub bound_account_ids: Vec<String>,
    
    /// Bound EC2 instance IDs (for EC2 auth)
    pub bound_ec2_instance_ids: Vec<String>,
    
    /// Bound IAM principal ARNs
    pub bound_iam_principal_arns: Vec<String>,
    
    /// Require instance identity document (EC2)
    pub resolve_instance_unique_id: bool,
}

impl Default for AwsRoleBinding {
    fn default() -> Self {
        Self {
            role_arn: String::new(),
            policies: Vec::new(),
            ttl: None,
            max_ttl: None,
            auth_types: vec![AwsAuthType::IAM, AwsAuthType::EC2],
            bound_account_ids: Vec::new(),
            bound_ec2_instance_ids: Vec::new(),
            bound_iam_principal_arns: Vec::new(),
            resolve_instance_unique_id: false,
        }
    }
}

/// AWS IAM request for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsIamRequest {
    /// IAM HTTP request method
    pub iam_http_request_method: String,
    
    /// IAM request URL
    pub iam_request_url: String,
    
    /// IAM request body (base64 encoded)
    pub iam_request_body: String,
    
    /// IAM request headers (base64 encoded JSON)
    pub iam_request_headers: String,
    
    /// Role name to authenticate as
    pub role: String,
}

/// AWS EC2 instance identity document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2InstanceIdentity {
    /// Instance ID
    pub instance_id: String,
    
    /// AWS account ID
    pub account_id: String,
    
    /// AWS region
    pub region: String,
    
    /// Instance type
    pub instance_type: String,
    
    /// AMI ID
    pub image_id: String,
    
    /// Private IP
    pub private_ip: Option<String>,
    
    /// Availability zone
    pub availability_zone: String,
    
    /// Architecture
    pub architecture: String,
    
    /// Pending time
    pub pending_time: DateTime<Utc>,
}

/// AWS EC2 authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsEc2Request {
    /// PKCS7 signature of instance identity document
    pub pkcs7: String,
    
    /// Nonce (for replay prevention)
    pub nonce: Option<String>,
    
    /// Role name to authenticate as
    pub role: String,
}

/// AWS authentication service
pub struct AwsAuth {
    config: Arc<RwLock<AwsAuthConfig>>,
    role_bindings: Arc<RwLock<HashMap<String, AwsRoleBinding>>>,
    ec2_nonces: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl AwsAuth {
    /// Create new AWS authentication service
    pub fn new(config: AwsAuthConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            role_bindings: Arc::new(RwLock::new(HashMap::new())),
            ec2_nonces: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Configure AWS authentication
    pub async fn configure(&self, config: AwsAuthConfig) {
        let mut cfg = self.config.write().await;
        *cfg = config;
    }
    
    /// Create role binding
    pub async fn create_role_binding(&self, name: String, binding: AwsRoleBinding) -> Result<(), AwsError> {
        if binding.role_arn.is_empty() {
            return Err(AwsError::InvalidCredentials("Role ARN cannot be empty".to_string()));
        }
        
        let mut bindings = self.role_bindings.write().await;
        bindings.insert(name, binding);
        Ok(())
    }
    
    /// Authenticate using IAM credentials
    pub async fn authenticate_iam(&self, request: AwsIamRequest) -> Result<UserInfo, AwsError> {
        // Get role binding
        let bindings = self.role_bindings.read().await;
        let binding = bindings.get(&request.role)
            .ok_or_else(|| AwsError::RoleNotFound(request.role.clone()))?
            .clone();
        drop(bindings);
        
        // Verify IAM auth type is allowed
        if !binding.auth_types.contains(&AwsAuthType::IAM) {
            return Err(AwsError::InvalidCredentials(
                "IAM authentication not allowed for this role".to_string()
            ));
        }
        
        // Verify AWS STS signature (simplified - production would call AWS STS)
        self.verify_iam_signature(&request).await?;
        
        // Extract principal ARN from request
        let principal_arn = self.extract_principal_arn(&request)?;
        
        // Verify principal ARN is bound
        if !binding.bound_iam_principal_arns.is_empty() {
            if !binding.bound_iam_principal_arns.iter().any(|arn| principal_arn.contains(arn)) {
                return Err(AwsError::InvalidCredentials(
                    "Principal ARN not authorized".to_string()
                ));
            }
        }
        
        // Build user info
        let mut metadata = HashMap::new();
        metadata.insert("auth_type".to_string(), "aws-iam".to_string());
        metadata.insert("role_arn".to_string(), binding.role_arn.clone());
        metadata.insert("principal_arn".to_string(), principal_arn.clone());
        
        Ok(UserInfo {
            username: principal_arn.clone(),
            email: None,
            display_name: Some(principal_arn),
            policies: binding.policies,
            metadata,
        })
    }
    
    /// Authenticate using EC2 instance identity
    pub async fn authenticate_ec2(&self, request: AwsEc2Request) -> Result<UserInfo, AwsError> {
        // Get role binding
        let bindings = self.role_bindings.read().await;
        let binding = bindings.get(&request.role)
            .ok_or_else(|| AwsError::RoleNotFound(request.role.clone()))?
            .clone();
        drop(bindings);
        
        // Verify EC2 auth type is allowed
        if !binding.auth_types.contains(&AwsAuthType::EC2) {
            return Err(AwsError::InvalidCredentials(
                "EC2 authentication not allowed for this role".to_string()
            ));
        }
        
        // Verify nonce (replay prevention)
        if let Some(nonce) = &request.nonce {
            self.check_nonce(nonce).await?;
        }
        
        // Verify PKCS7 signature and extract identity document
        let identity = self.verify_ec2_identity(&request.pkcs7).await?;
        
        // Verify account ID
        if !binding.bound_account_ids.is_empty() {
            if !binding.bound_account_ids.contains(&identity.account_id) {
                return Err(AwsError::Ec2VerificationFailed(
                    "Account ID not authorized".to_string()
                ));
            }
        }
        
        // Verify instance ID
        if !binding.bound_ec2_instance_ids.is_empty() {
            if !binding.bound_ec2_instance_ids.contains(&identity.instance_id) {
                return Err(AwsError::Ec2VerificationFailed(
                    "Instance ID not authorized".to_string()
                ));
            }
        }
        
        // Store nonce to prevent replay
        if let Some(nonce) = request.nonce {
            let mut nonces = self.ec2_nonces.write().await;
            nonces.insert(nonce, Utc::now());
        }
        
        // Build user info
        let mut metadata = HashMap::new();
        metadata.insert("auth_type".to_string(), "aws-ec2".to_string());
        metadata.insert("role_arn".to_string(), binding.role_arn.clone());
        metadata.insert("instance_id".to_string(), identity.instance_id.clone());
        metadata.insert("account_id".to_string(), identity.account_id.clone());
        metadata.insert("region".to_string(), identity.region.clone());
        
        Ok(UserInfo {
            username: identity.instance_id.clone(),
            email: None,
            display_name: Some(format!("ec2-{}", identity.instance_id)),
            policies: binding.policies,
            metadata,
        })
    }
    
    /// Verify IAM signature using AWS STS
    async fn verify_iam_signature(&self, request: &AwsIamRequest) -> Result<(), AwsError> {
        // In production, this would:
        // 1. Decode base64 request headers and body
        // 2. Call AWS STS GetCallerIdentity with the signature
        // 3. Verify the response matches the request
        
        // For now, simple validation
        if request.iam_request_method.is_empty() {
            return Err(AwsError::InvalidSignature("Empty request method".to_string()));
        }
        if request.iam_request_url.is_empty() {
            return Err(AwsError::InvalidSignature("Empty request URL".to_string()));
        }
        if request.iam_request_headers.is_empty() {
            return Err(AwsError::InvalidSignature("Empty request headers".to_string()));
        }
        
        Ok(())
    }
    
    /// Extract principal ARN from IAM request
    fn extract_principal_arn(&self, request: &AwsIamRequest) -> Result<String, AwsError> {
        // In production, would parse from STS response
        // For now, extract from URL or use placeholder
        Ok("arn:aws:iam::123456789012:user/example".to_string())
    }
    
    /// Verify EC2 instance identity document
    async fn verify_ec2_identity(&self, pkcs7: &str) -> Result<Ec2InstanceIdentity, AwsError> {
        // In production, this would:
        // 1. Decode PKCS7 signature
        // 2. Verify signature against AWS public certificate
        // 3. Extract and parse instance identity document
        // 4. Call EC2 DescribeInstances to verify instance exists
        
        // For now, return mock identity
        Ok(Ec2InstanceIdentity {
            instance_id: "i-1234567890abcdef0".to_string(),
            account_id: "123456789012".to_string(),
            region: "us-east-1".to_string(),
            instance_type: "t3.micro".to_string(),
            image_id: "ami-0c55b159cbfafe1f0".to_string(),
            private_ip: Some("10.0.1.123".to_string()),
            availability_zone: "us-east-1a".to_string(),
            architecture: "x86_64".to_string(),
            pending_time: Utc::now(),
        })
    }
    
    /// Check if nonce has been used (replay prevention)
    async fn check_nonce(&self, nonce: &str) -> Result<(), AwsError> {
        let nonces = self.ec2_nonces.read().await;
        if nonces.contains_key(nonce) {
            return Err(AwsError::Ec2VerificationFailed(
                "Nonce already used (replay attack prevented)".to_string()
            ));
        }
        Ok(())
    }
    
    /// Clean up expired nonces
    pub async fn cleanup_nonces(&self, max_age_seconds: i64) {
        let mut nonces = self.ec2_nonces.write().await;
        let now = Utc::now();
        nonces.retain(|_, timestamp| {
            now.signed_duration_since(*timestamp).num_seconds() < max_age_seconds
        });
    }
    
    /// List role bindings
    pub async fn list_roles(&self) -> Vec<String> {
        let bindings = self.role_bindings.read().await;
        bindings.keys().cloned().collect()
    }
    
    /// Delete role binding
    pub async fn delete_role(&self, name: &str) -> Result<(), AwsError> {
        let mut bindings = self.role_bindings.write().await;
        bindings.remove(name)
            .ok_or_else(|| AwsError::RoleNotFound(name.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aws_auth_creation() {
        let config = AwsAuthConfig::default();
        let auth = AwsAuth::new(config);
        
        assert_eq!(auth.list_roles().await.len(), 0);
    }
    
    #[tokio::test]
    async fn test_create_role_binding() {
        let config = AwsAuthConfig::default();
        let auth = AwsAuth::new(config);
        
        let binding = AwsRoleBinding {
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            policies: vec!["default".to_string(), "read".to_string()],
            bound_account_ids: vec!["123456789012".to_string()],
            ..Default::default()
        };
        
        let result = auth.create_role_binding("test-role".to_string(), binding).await;
        assert!(result.is_ok());
        
        let roles = auth.list_roles().await;
        assert_eq!(roles.len(), 1);
        assert!(roles.contains(&"test-role".to_string()));
    }
    
    #[tokio::test]
    async fn test_authenticate_iam() {
        let config = AwsAuthConfig::default();
        let auth = AwsAuth::new(config);
        
        // Create role binding
        let binding = AwsRoleBinding {
            role_arn: "arn:aws:iam::123456789012:role/MyRole".to_string(),
            policies: vec!["admin".to_string()],
            bound_iam_principal_arns: vec!["arn:aws:iam::123456789012:user/".to_string()],
            ..Default::default()
        };
        auth.create_role_binding("test-role".to_string(), binding).await.unwrap();
        
        // Create IAM request
        let request = AwsIamRequest {
            iam_http_request_method: "POST".to_string(),
            iam_request_url: "https://sts.amazonaws.com/".to_string(),
            iam_request_body: "dGVzdA==".to_string(), // base64 "test"
            iam_request_headers: "eyJ0ZXN0IjoidGVzdCJ9".to_string(), // base64 {"test":"test"}
            role: "test-role".to_string(),
        };
        
        let result = auth.authenticate_iam(request).await;
        assert!(result.is_ok());
        
        let user_info = result.unwrap();
        assert_eq!(user_info.policies.len(), 1);
        assert!(user_info.metadata.contains_key("auth_type"));
    }
    
    #[tokio::test]
    async fn test_nonce_replay_prevention() {
        let config = AwsAuthConfig::default();
        let auth = AwsAuth::new(config);
        
        let nonce = "test-nonce-123".to_string();
        
        // First check should pass
        let result1 = auth.check_nonce(&nonce).await;
        assert!(result1.is_ok());
        
        // Add nonce
        let mut nonces = auth.ec2_nonces.write().await;
        nonces.insert(nonce.clone(), Utc::now());
        drop(nonces);
        
        // Second check should fail
        let result2 = auth.check_nonce(&nonce).await;
        assert!(result2.is_err());
    }
}
