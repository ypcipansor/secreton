//! Recovery code MFA implementation
//!
//! Provides backup recovery codes for account recovery when other MFA methods are unavailable.

use crate::service::AuthMethodResult;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secreton_domain::SecretonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Number of recovery codes to generate
const DEFAULT_CODE_COUNT: usize = 10;
/// Length of each recovery code
const CODE_LENGTH: usize = 8;

/// Recovery code status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecoveryCodeStatus {
    /// Code is available for use
    Available,
    /// Code has been used
    Used,
    /// Code has been revoked
    Revoked,
}

/// A single recovery code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCode {
    /// The recovery code (hashed for storage)
    pub code_hash: String,
    /// Status of the code
    pub status: RecoveryCodeStatus,
    /// When the code was used (if applicable)
    pub used_at: Option<DateTime<Utc>>,
    /// IP address from which the code was used
    pub used_from_ip: Option<String>,
}

/// Recovery code enrollment containing all codes for an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeEnrollment {
    /// Entity ID
    pub entity_id: Uuid,
    /// Recovery codes
    pub codes: Vec<RecoveryCode>,
    /// When the codes were generated
    pub generated_at: DateTime<Utc>,
    /// Total number of codes
    pub total_codes: usize,
    /// Number of remaining (unused) codes
    pub remaining_codes: usize,
}

/// Recovery code validation request
#[derive(Debug)]
pub struct RecoveryCodeValidationRequest {
    /// Entity ID
    pub entity_id: Uuid,
    /// The recovery code to validate
    pub code: String,
    /// IP address of the request
    pub request_ip: Option<String>,
}

/// Recovery code generation response (contains plaintext codes)
#[derive(Debug, Serialize)]
pub struct RecoveryCodeGenerationResponse {
    /// Entity ID
    pub entity_id: Uuid,
    /// Plaintext recovery codes (only shown once)
    pub codes: Vec<String>,
    /// When the codes were generated
    pub generated_at: DateTime<Utc>,
    /// Warning message
    pub warning: String,
}

/// Recovery code service trait
#[async_trait]
pub trait RecoveryCodeService: Send + Sync {
    /// Generate new recovery codes for an entity
    /// This will invalidate any existing recovery codes
    async fn generate_codes(
        &self,
        entity_id: Uuid,
    ) -> AuthMethodResult<RecoveryCodeGenerationResponse>;

    /// Validate a recovery code
    async fn validate(&self, request: RecoveryCodeValidationRequest) -> AuthMethodResult<bool>;

    /// Get the enrollment status for an entity
    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> AuthMethodResult<Option<RecoveryCodeEnrollment>>;

    /// Revoke all recovery codes for an entity
    async fn revoke_codes(&self, entity_id: Uuid) -> AuthMethodResult<()>;

    /// Check if entity has any remaining codes
    async fn has_remaining_codes(&self, entity_id: Uuid) -> AuthMethodResult<bool>;
}

/// Default recovery code service implementation
pub struct DefaultRecoveryCodeService {
    enrollments: RwLock<HashMap<Uuid, RecoveryCodeEnrollment>>,
    code_count: usize,
}

impl DefaultRecoveryCodeService {
    /// Create a new recovery code service
    pub fn new() -> Self {
        Self {
            enrollments: RwLock::new(HashMap::new()),
            code_count: DEFAULT_CODE_COUNT,
        }
    }

    /// Create with custom code count
    pub fn with_code_count(code_count: usize) -> Self {
        Self {
            enrollments: RwLock::new(HashMap::new()),
            code_count,
        }
    }

    /// Generate a random recovery code
    fn generate_code() -> String {
        use rand::Rng;
        let charset: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Exclude similar chars (0, O, 1, I)
        let mut rng = rand::thread_rng();

        (0..CODE_LENGTH)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset[idx] as char
            })
            .collect()
    }

    /// Hash a recovery code for storage
    fn hash_code(code: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(code.to_uppercase().as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Format code with dashes for readability (e.g., "ABCD-EFGH")
    fn format_code(code: &str) -> String {
        if code.len() <= 4 {
            return code.to_string();
        }
        let (first, second) = code.split_at(4);
        format!("{}-{}", first, second)
    }
}

impl Default for DefaultRecoveryCodeService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RecoveryCodeService for DefaultRecoveryCodeService {
    async fn generate_codes(
        &self,
        entity_id: Uuid,
    ) -> AuthMethodResult<RecoveryCodeGenerationResponse> {
        let now = Utc::now();
        let mut plaintext_codes = Vec::with_capacity(self.code_count);
        let mut hashed_codes = Vec::with_capacity(self.code_count);

        // Generate codes
        for _ in 0..self.code_count {
            let code = Self::generate_code();
            plaintext_codes.push(Self::format_code(&code));
            hashed_codes.push(RecoveryCode {
                code_hash: Self::hash_code(&code),
                status: RecoveryCodeStatus::Available,
                used_at: None,
                used_from_ip: None,
            });
        }

        // Create enrollment
        let enrollment = RecoveryCodeEnrollment {
            entity_id,
            codes: hashed_codes,
            generated_at: now,
            total_codes: self.code_count,
            remaining_codes: self.code_count,
        };

        // Store enrollment (replaces any existing)
        let mut enrollments = self.enrollments.write().await;
        enrollments.insert(entity_id, enrollment);

        Ok(RecoveryCodeGenerationResponse {
            entity_id,
            codes: plaintext_codes,
            generated_at: now,
            warning: "Store these codes securely. They will not be shown again.".to_string(),
        })
    }

    async fn validate(&self, request: RecoveryCodeValidationRequest) -> AuthMethodResult<bool> {
        let mut enrollments = self.enrollments.write().await;
        let enrollment =
            enrollments
                .get_mut(&request.entity_id)
                .ok_or_else(|| SecretonError::NotFound {
                    resource: format!("recovery-codes:{}", request.entity_id),
                })?;

        // Normalize the code (remove dashes, uppercase)
        let normalized_code: String = request
            .code
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
            .to_uppercase();

        let code_hash = Self::hash_code(&normalized_code);

        // Find matching code
        for code in &mut enrollment.codes {
            if code.code_hash == code_hash {
                match code.status {
                    RecoveryCodeStatus::Available => {
                        // Mark as used
                        code.status = RecoveryCodeStatus::Used;
                        code.used_at = Some(Utc::now());
                        code.used_from_ip = request.request_ip;
                        enrollment.remaining_codes = enrollment.remaining_codes.saturating_sub(1);
                        return Ok(true);
                    }
                    RecoveryCodeStatus::Used => {
                        // Code already used
                        return Ok(false);
                    }
                    RecoveryCodeStatus::Revoked => {
                        // Code was revoked
                        return Ok(false);
                    }
                }
            }
        }

        // Code not found
        Ok(false)
    }

    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> AuthMethodResult<Option<RecoveryCodeEnrollment>> {
        let enrollments = self.enrollments.read().await;
        Ok(enrollments.get(&entity_id).cloned())
    }

    async fn revoke_codes(&self, entity_id: Uuid) -> AuthMethodResult<()> {
        let mut enrollments = self.enrollments.write().await;
        if let Some(enrollment) = enrollments.get_mut(&entity_id) {
            for code in &mut enrollment.codes {
                if code.status == RecoveryCodeStatus::Available {
                    code.status = RecoveryCodeStatus::Revoked;
                }
            }
            enrollment.remaining_codes = 0;
        }
        Ok(())
    }

    async fn has_remaining_codes(&self, entity_id: Uuid) -> AuthMethodResult<bool> {
        let enrollments = self.enrollments.read().await;
        Ok(enrollments
            .get(&entity_id)
            .map(|e| e.remaining_codes > 0)
            .unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_recovery_codes() {
        let service = DefaultRecoveryCodeService::new();
        let entity_id = Uuid::new_v4();

        let response = service.generate_codes(entity_id).await.unwrap();

        assert_eq!(response.entity_id, entity_id);
        assert_eq!(response.codes.len(), DEFAULT_CODE_COUNT);

        // Verify codes are formatted correctly
        for code in &response.codes {
            assert!(code.contains('-'), "Code should be formatted with dash");
            let clean: String = code.chars().filter(|c| c.is_alphanumeric()).collect();
            assert_eq!(clean.len(), CODE_LENGTH);
        }
    }

    #[tokio::test]
    async fn test_validate_recovery_code() {
        let service = DefaultRecoveryCodeService::new();
        let entity_id = Uuid::new_v4();

        // Generate codes
        let response = service.generate_codes(entity_id).await.unwrap();
        let code = response.codes[0].clone();

        // Validate the code
        let result = service
            .validate(RecoveryCodeValidationRequest {
                entity_id,
                code: code.clone(),
                request_ip: Some("127.0.0.1".to_string()),
            })
            .await
            .unwrap();

        assert!(result, "Valid code should be accepted");

        // Try to use the same code again
        let result = service
            .validate(RecoveryCodeValidationRequest {
                entity_id,
                code,
                request_ip: None,
            })
            .await
            .unwrap();

        assert!(!result, "Used code should be rejected");
    }

    #[tokio::test]
    async fn test_validate_with_different_formats() {
        let service = DefaultRecoveryCodeService::new();
        let entity_id = Uuid::new_v4();

        let response = service.generate_codes(entity_id).await.unwrap();
        let code = response.codes[0].clone();

        // Test lowercase
        let result = service
            .validate(RecoveryCodeValidationRequest {
                entity_id,
                code: code.to_lowercase(),
                request_ip: None,
            })
            .await
            .unwrap();

        assert!(result, "Lowercase code should be accepted");
    }

    #[tokio::test]
    async fn test_remaining_codes_count() {
        let service = DefaultRecoveryCodeService::with_code_count(3);
        let entity_id = Uuid::new_v4();

        let response = service.generate_codes(entity_id).await.unwrap();

        // Verify initial count
        let enrollment = service.get_enrollment(entity_id).await.unwrap().unwrap();
        assert_eq!(enrollment.remaining_codes, 3);

        // Use a code
        service
            .validate(RecoveryCodeValidationRequest {
                entity_id,
                code: response.codes[0].clone(),
                request_ip: None,
            })
            .await
            .unwrap();

        // Verify count decreased
        let enrollment = service.get_enrollment(entity_id).await.unwrap().unwrap();
        assert_eq!(enrollment.remaining_codes, 2);
    }

    #[tokio::test]
    async fn test_revoke_codes() {
        let service = DefaultRecoveryCodeService::new();
        let entity_id = Uuid::new_v4();

        let response = service.generate_codes(entity_id).await.unwrap();
        let code = response.codes[0].clone();

        // Revoke all codes
        service.revoke_codes(entity_id).await.unwrap();

        // Try to use a code
        let result = service
            .validate(RecoveryCodeValidationRequest {
                entity_id,
                code,
                request_ip: None,
            })
            .await
            .unwrap();

        assert!(!result, "Revoked code should be rejected");

        // Verify no remaining codes
        let has_codes = service.has_remaining_codes(entity_id).await.unwrap();
        assert!(!has_codes);
    }

    #[tokio::test]
    async fn test_regenerate_codes() {
        let service = DefaultRecoveryCodeService::new();
        let entity_id = Uuid::new_v4();

        // Generate first set
        let response1 = service.generate_codes(entity_id).await.unwrap();
        let old_code = response1.codes[0].clone();

        // Generate new set (should replace old)
        let response2 = service.generate_codes(entity_id).await.unwrap();

        // Old code should no longer work
        let result = service
            .validate(RecoveryCodeValidationRequest {
                entity_id,
                code: old_code,
                request_ip: None,
            })
            .await
            .unwrap();

        assert!(!result, "Old code should be invalidated");

        // New code should work
        let result = service
            .validate(RecoveryCodeValidationRequest {
                entity_id,
                code: response2.codes[0].clone(),
                request_ip: None,
            })
            .await
            .unwrap();

        assert!(result, "New code should work");
    }
}
