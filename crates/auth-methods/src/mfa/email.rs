//! Email-based MFA implementation

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::*;

/// Email configuration
#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from_email: String,
    pub subject_template: String,
    pub body_template: String,
    pub code_length: usize,
    pub code_expiry_seconds: i64,
}

/// Email enrollment
#[derive(Debug, Clone)]
pub struct EmailEnrollment {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub email: String,
    pub creation_time: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

/// Email validation request
#[derive(Debug)]
pub struct EmailValidationRequest {
    pub entity_id: Uuid,
    pub code: String,
}

/// Pending email code
#[derive(Debug)]
struct PendingEmailCode {
    code: String,
    _email: String,
    expiry: DateTime<Utc>,
}

/// Email service trait
#[async_trait]
pub trait EmailService: Send + Sync {
    /// Enroll an entity for email MFA
    async fn enroll(&self, entity_id: Uuid, email: String) -> AuthMethodResult<()>;

    /// Send email code for validation
    async fn send_code(&self, entity_id: Uuid) -> AuthMethodResult<()>;

    /// Validate email code
    async fn validate(&self, request: EmailValidationRequest) -> AuthMethodResult<bool>;

    /// Get enrollment for an entity
    async fn get_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<Option<EmailEnrollment>>;

    /// Remove email enrollment for an entity
    async fn remove_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<()>;
}

/// In-memory email service implementation
pub struct InMemoryEmailService {
    enrollments: RwLock<HashMap<Uuid, EmailEnrollment>>,
    pending_codes: RwLock<HashMap<Uuid, PendingEmailCode>>,
    config: EmailConfig,
}

impl InMemoryEmailService {
    pub fn new(config: EmailConfig) -> Self {
        Self {
            enrollments: RwLock::new(HashMap::new()),
            pending_codes: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Generate a random email code
    fn generate_code(&self) -> String {
        let mut rng = rand::thread_rng();
        let digits: Vec<u32> = (0..self.config.code_length)
            .map(|_| rng.gen_range(0..10))
            .collect();
        digits.iter().map(|d| d.to_string()).collect::<String>()
    }

    /// Send email via SMTP (mock implementation)
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthMethodError> {
        // In a real implementation, this would use an SMTP library
        // For now, we'll just log it
        println!("Email to {}: {} - {}", to, subject, body);
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
impl EmailService for InMemoryEmailService {
    async fn enroll(&self, entity_id: Uuid, email: String) -> Result<(), AuthMethodError> {
        let enrollment = EmailEnrollment {
            id: Uuid::new_v4(),
            entity_id,
            email: email.clone(),
            creation_time: Utc::now(),
            last_used: None,
        };

        let mut enrollments = self.enrollments.write().await;
        enrollments.insert(entity_id, enrollment.clone());

        Ok(())
    }

    async fn send_code(&self, entity_id: Uuid) -> Result<(), AuthMethodError> {
        let enrollments = self.enrollments.read().await;

        let email = if let Some(enrollment) = enrollments.get(&entity_id) {
            enrollment.email.clone()
        } else {
            return Err(AuthMethodError::UserNotFound(format!(
                "Email enrollment for entity {}",
                entity_id
            )));
        };

        drop(enrollments);

        let code = self.generate_code();
        let subject = self.config.subject_template.replace("{code}", &code);
        let body = self.config.body_template.replace("{code}", &code);

        // Send the email
        self.send_email(&email, &subject, &body).await?;

        // Store the pending code
        let pending_code = PendingEmailCode {
            code,
            _email: email,
            expiry: Utc::now() + Duration::seconds(self.config.code_expiry_seconds),
        };

        let mut pending_codes = self.pending_codes.write().await;
        pending_codes.insert(entity_id, pending_code);

        Ok(())
    }

    async fn validate(&self, request: EmailValidationRequest) -> Result<bool, AuthMethodError> {
        self.cleanup_expired_codes().await;

        let mut pending_codes = self.pending_codes.write().await;

        if let Some(pending_code) = pending_codes.get(&request.entity_id) {
            if pending_code.code == request.code && pending_code.expiry > Utc::now() {
                // Code is valid, remove it and update enrollment
                pending_codes.remove(&request.entity_id);

                let mut enrollments = self.enrollments.write().await;
                if let Some(enrollment) = enrollments.get_mut(&request.entity_id) {
                    enrollment.last_used = Some(Utc::now());
                }

                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<EmailEnrollment>, AuthMethodError> {
        let enrollments = self.enrollments.read().await;
        Ok(enrollments.get(&entity_id).cloned())
    }

    async fn remove_enrollment(&self, entity_id: Uuid) -> Result<(), AuthMethodError> {
        let mut enrollments = self.enrollments.write().await;
        let mut pending_codes = self.pending_codes.write().await;

        enrollments.remove(&entity_id);
        pending_codes.remove(&entity_id);

        Ok(())
    }
}
