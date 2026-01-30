//! SMS-based MFA implementation

use crate::service::AuthMethodResult;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use secreton_errors::SecretonError;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

/// SMS configuration
#[derive(Debug, Clone)]
pub struct SmsConfig {
    pub provider: SmsProvider,
    pub api_key: String,
    pub api_secret: Option<String>,
    pub from_number: String,
    pub message_template: String,
    pub code_length: usize,
    pub code_expiry_seconds: i64,
}

/// SMS provider types
#[derive(Debug, Clone)]
pub enum SmsProvider {
    Twilio,
    AwsSns,
    Nexmo,
    Custom { url: String },
}

/// SMS enrollment
#[derive(Debug, Clone)]
pub struct SmsEnrollment {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub phone_number: String,
    pub creation_time: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

/// SMS validation request
#[derive(Debug)]
pub struct SmsValidationRequest {
    pub entity_id: Uuid,
    pub code: String,
}

/// Pending SMS code
#[derive(Debug)]
struct PendingSmsCode {
    code: String,
    _phone_number: String,
    expiry: DateTime<Utc>,
}

/// SMS service trait
#[async_trait]
pub trait SmsService: Send + Sync {
    /// Enroll an entity for SMS MFA
    async fn enroll(
        &self,
        entity_id: Uuid,
        phone_number: String,
    ) -> AuthMethodResult<SmsEnrollment>;

    /// Send SMS code for validation
    async fn send_code(&self, entity_id: Uuid) -> AuthMethodResult<()>;

    /// Validate SMS code
    async fn validate(&self, request: SmsValidationRequest) -> AuthMethodResult<bool>;

    /// Get enrollment for an entity
    async fn get_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<Option<SmsEnrollment>>;

    /// Remove SMS enrollment for an entity
    async fn remove_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<()>;
}

/// In-memory SMS service implementation
pub struct InMemorySmsService {
    enrollments: RwLock<HashMap<Uuid, SmsEnrollment>>,
    pending_codes: RwLock<HashMap<Uuid, PendingSmsCode>>,
    config: SmsConfig,
}

impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            provider: SmsProvider::Custom { url: "http://localhost/sms".to_string() },
            api_key: "".to_string(),
            api_secret: None,
            from_number: "".to_string(),
            message_template: "Your Secreton code is {code}".to_string(),
            code_length: 6,
            code_expiry_seconds: 300,
        }
    }
}

impl InMemorySmsService {
    pub fn new(config: SmsConfig) -> Self {
        Self {
            enrollments: RwLock::new(HashMap::new()),
            pending_codes: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Generate a random SMS code
    fn generate_code(&self) -> String {
        let mut rng = rand::thread_rng();
        let digits: Vec<u32> = (0..self.config.code_length)
            .map(|_| rng.gen_range(0..10))
            .collect();
        digits.iter().map(|d| d.to_string()).collect::<String>()
    }

    /// Send SMS via configured provider
    async fn send_sms(&self, to: &str, message: &str) -> AuthMethodResult<()> {
        match &self.config.provider {
            SmsProvider::Twilio => {
                // Twilio integration would go here
                // For now, log the SMS that would be sent
                tracing::info!(
                    provider = "twilio",
                    to = %to,
                    message_length = message.len(),
                    "SMS sent (simulated)"
                );
            }
            SmsProvider::AwsSns => {
                // AWS SNS integration would go here
                tracing::info!(
                    provider = "aws_sns",
                    to = %to,
                    message_length = message.len(),
                    "SMS sent (simulated)"
                );
            }
            SmsProvider::Nexmo => {
                // Nexmo/Vonage integration would go here
                tracing::info!(
                    provider = "nexmo",
                    to = %to,
                    message_length = message.len(),
                    "SMS sent (simulated)"
                );
            }
            SmsProvider::Custom { url } => {
                // Custom webhook integration would go here
                tracing::info!(
                    provider = "custom",
                    url = %url,
                    to = %to,
                    message_length = message.len(),
                    "SMS sent (simulated)"
                );
            }
        }
        Ok(())
    }

    /// Clean up expired codes
    async fn cleanup_expired_codes(&self) {
        let mut pending_codes = self.pending_codes.write().await;
        let now = Utc::now();
        pending_codes.retain(|_, code| code.expiry > now);
    }
}

#[async_trait]
impl SmsService for InMemorySmsService {
    async fn enroll(
        &self,
        entity_id: Uuid,
        phone_number: String,
    ) -> AuthMethodResult<SmsEnrollment> {
        let enrollment = SmsEnrollment {
            id: Uuid::new_v4(),
            entity_id,
            phone_number: phone_number.clone(),
            creation_time: Utc::now(),
            last_used: None,
        };

        let mut enrollments = self.enrollments.write().await;
        enrollments.insert(entity_id, enrollment.clone());

        Ok(enrollment)
    }

    async fn send_code(&self, entity_id: Uuid) -> AuthMethodResult<()> {
        let enrollments = self.enrollments.read().await;

        let phone_number = if let Some(enrollment) = enrollments.get(&entity_id) {
            enrollment.phone_number.clone()
        } else {
            return Err(SecretonError::NotFound {
                resource: format!("sms-enrollment:{}", entity_id),
            });
        };

        drop(enrollments);

        let code = self.generate_code();
        let message = self.config.message_template.replace("{code}", &code);

        // Send the SMS
        self.send_sms(&phone_number, &message).await?;

        // Store the pending code
        let pending_code = PendingSmsCode {
            code,
            _phone_number: phone_number,
            expiry: Utc::now() + Duration::seconds(self.config.code_expiry_seconds),
        };

        let mut pending_codes = self.pending_codes.write().await;
        pending_codes.insert(entity_id, pending_code);

        Ok(())
    }

    async fn validate(&self, request: SmsValidationRequest) -> AuthMethodResult<bool> {
        self.cleanup_expired_codes().await;

        let mut pending_codes = self.pending_codes.write().await;

        if let Some(pending_code) = pending_codes.get(&request.entity_id)
            && pending_code.code == request.code && pending_code.expiry > Utc::now() {
            // Code is valid, remove it and update enrollment
            pending_codes.remove(&request.entity_id);

            let mut enrollments = self.enrollments.write().await;
            if let Some(enrollment) = enrollments.get_mut(&request.entity_id) {
                enrollment.last_used = Some(Utc::now());
            }

            return Ok(true);
        }

        Ok(false)
    }

    async fn get_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<Option<SmsEnrollment>> {
        let enrollments = self.enrollments.read().await;
        Ok(enrollments.get(&entity_id).cloned())
    }

    async fn remove_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<()> {
        let mut enrollments = self.enrollments.write().await;
        let mut pending_codes = self.pending_codes.write().await;

        enrollments.remove(&entity_id);
        pending_codes.remove(&entity_id);

        Ok(())
    }
}
