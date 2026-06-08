//! Push notification MFA implementation
//!
//! Provides push-based multi-factor authentication using mobile devices.

use crate::service::AuthMethodResult;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use secreton_errors::SecretonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Push notification status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PushStatus {
    /// Notification sent, waiting for response
    Pending,
    /// User approved the push notification
    Approved,
    /// User denied the push notification
    Denied,
    /// Notification expired
    Expired,
    /// Notification failed to deliver
    Failed,
}

/// Push notification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushNotification {
    /// Unique notification ID
    pub id: Uuid,
    /// Entity ID (user)
    pub entity_id: Uuid,
    /// Device ID
    pub device_id: String,
    /// Notification title
    pub title: String,
    /// Notification body
    pub body: String,
    /// Status
    pub status: PushStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Expires at timestamp
    pub expires_at: DateTime<Utc>,
    /// IP address of the request
    pub request_ip: Option<String>,
    /// User agent of the request
    pub request_user_agent: Option<String>,
}

/// Push device enrollment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushDeviceEnrollment {
    /// Entity ID
    pub entity_id: Uuid,
    /// Device ID
    pub device_id: String,
    /// Device name (e.g., "iPhone 15")
    pub device_name: String,
    /// Push token for sending notifications
    pub push_token: String,
    /// Platform (iOS, Android, etc.)
    pub platform: String,
    /// Enrolled at timestamp
    pub enrolled_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
}

/// Push validation request
#[derive(Debug)]
pub struct PushValidationRequest {
    /// Entity ID
    pub entity_id: Uuid,
    /// Notification ID
    pub notification_id: Uuid,
    /// User's response (approve/deny)
    pub response: PushResponse,
}

/// Push response from user
#[derive(Debug, Clone, PartialEq)]
pub enum PushResponse {
    Approve,
    Deny,
}

/// Push MFA service trait
#[async_trait]
pub trait PushService: Send + Sync {
    /// Enroll a device for push notifications
    async fn enroll_device(
        &self,
        entity_id: Uuid,
        device_id: String,
        device_name: String,
        push_token: String,
        platform: String,
    ) -> AuthMethodResult<PushDeviceEnrollment>;

    /// Send a push notification for authentication
    async fn send_notification(
        &self,
        entity_id: Uuid,
        device_id: &str,
        title: &str,
        body: &str,
        request_ip: Option<String>,
        request_user_agent: Option<String>,
    ) -> AuthMethodResult<PushNotification>;

    /// Get the status of a push notification
    async fn get_notification_status(&self, notification_id: Uuid) -> AuthMethodResult<PushStatus>;

    /// Validate a push notification response
    async fn validate(&self, request: PushValidationRequest) -> AuthMethodResult<bool>;

    /// Remove device enrollment
    async fn remove_enrollment(&self, entity_id: Uuid, device_id: &str) -> AuthMethodResult<()>;

    /// List enrolled devices for an entity
    async fn list_devices(&self, entity_id: Uuid) -> AuthMethodResult<Vec<PushDeviceEnrollment>>;
}

/// Default push service implementation
pub struct DefaultPushService {
    /// Device enrollments: entity_id -> device_id -> enrollment
    enrollments: RwLock<HashMap<Uuid, HashMap<String, PushDeviceEnrollment>>>,
    /// Pending notifications: notification_id -> notification
    notifications: RwLock<HashMap<Uuid, PushNotification>>,
    /// Notification TTL in seconds
    notification_ttl: i64,
    /// Push notification provider (for actual delivery)
    push_provider: Arc<dyn PushProvider>,
}

/// Push notification provider trait
#[async_trait]
pub trait PushProvider: Send + Sync {
    /// Send push notification to device
    async fn send(
        &self,
        push_token: &str,
        title: &str,
        body: &str,
        data: HashMap<String, String>,
    ) -> Result<(), SecretonError>;
}

/// Mock push provider for testing
pub struct MockPushProvider;

#[async_trait]
impl PushProvider for MockPushProvider {
    async fn send(
        &self,
        push_token: &str,
        title: &str,
        body: &str,
        _data: HashMap<String, String>,
    ) -> Result<(), SecretonError> {
        tracing::info!(
            "Mock push notification sent to {}: {} - {}",
            push_token,
            title,
            body
        );
        Ok(())
    }
}

impl DefaultPushService {
    /// Create a new push service with the given provider
    pub fn new(push_provider: Arc<dyn PushProvider>) -> Self {
        Self {
            enrollments: RwLock::new(HashMap::new()),
            notifications: RwLock::new(HashMap::new()),
            notification_ttl: 300, // 5 minutes default
            push_provider,
        }
    }

    /// Create a new push service with mock provider (for testing)
    pub fn new_mock() -> Self {
        Self::new(Arc::new(MockPushProvider))
    }

    /// Set notification TTL
    pub fn with_ttl(mut self, ttl_seconds: i64) -> Self {
        self.notification_ttl = ttl_seconds;
        self
    }

    /// Clean up expired notifications
    async fn cleanup_expired_notifications(&self) {
        let now = Utc::now();
        let mut notifications = self.notifications.write().await;
        notifications.retain(|_, n| n.expires_at > now);
    }
}

#[async_trait]
impl PushService for DefaultPushService {
    async fn enroll_device(
        &self,
        entity_id: Uuid,
        device_id: String,
        device_name: String,
        push_token: String,
        platform: String,
    ) -> AuthMethodResult<PushDeviceEnrollment> {
        let enrollment = PushDeviceEnrollment {
            entity_id,
            device_id: device_id.clone(),
            device_name,
            push_token,
            platform,
            enrolled_at: Utc::now(),
            last_used: None,
        };

        let mut enrollments = self.enrollments.write().await;
        enrollments
            .entry(entity_id)
            .or_insert_with(HashMap::new)
            .insert(device_id, enrollment.clone());

        Ok(enrollment)
    }

    async fn send_notification(
        &self,
        entity_id: Uuid,
        device_id: &str,
        title: &str,
        body: &str,
        request_ip: Option<String>,
        request_user_agent: Option<String>,
    ) -> AuthMethodResult<PushNotification> {
        // Get the device enrollment
        let enrollments = self.enrollments.read().await;
        let device = enrollments
            .get(&entity_id)
            .and_then(|devices| devices.get(device_id))
            .ok_or_else(|| SecretonError::NotFound {
                resource: format!("push-device:{}", device_id),
            })?;

        let notification_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.notification_ttl);

        // Send via push provider
        let mut data = HashMap::new();
        data.insert("notification_id".to_string(), notification_id.to_string());
        data.insert("entity_id".to_string(), entity_id.to_string());
        data.insert("action".to_string(), "mfa_approval".to_string());

        self.push_provider
            .send(&device.push_token, title, body, data)
            .await?;

        let notification = PushNotification {
            id: notification_id,
            entity_id,
            device_id: device_id.to_string(),
            title: title.to_string(),
            body: body.to_string(),
            status: PushStatus::Pending,
            created_at: now,
            expires_at,
            request_ip,
            request_user_agent,
        };

        // Store notification
        let mut notifications = self.notifications.write().await;
        notifications.insert(notification_id, notification.clone());

        Ok(notification)
    }

    async fn get_notification_status(&self, notification_id: Uuid) -> AuthMethodResult<PushStatus> {
        // Clean up expired first
        self.cleanup_expired_notifications().await;

        let notifications = self.notifications.read().await;
        let notification =
            notifications
                .get(&notification_id)
                .ok_or_else(|| SecretonError::NotFound {
                    resource: format!("push-notification:{}", notification_id),
                })?;

        // Check if expired
        if Utc::now() > notification.expires_at {
            return Ok(PushStatus::Expired);
        }

        Ok(notification.status.clone())
    }

    async fn validate(&self, request: PushValidationRequest) -> AuthMethodResult<bool> {
        // Clean up expired notifications
        self.cleanup_expired_notifications().await;

        // First, get and update the notification, extracting needed data
        let (is_approved, device_id) = {
            let mut notifications = self.notifications.write().await;
            let notification =
                notifications
                    .get_mut(&request.notification_id)
                    .ok_or_else(|| SecretonError::NotFound {
                        resource: format!("push-notification:{}", request.notification_id),
                    })?;

            // Verify entity_id matches
            if notification.entity_id != request.entity_id {
                return Ok(false);
            }

            // Check if expired
            if Utc::now() > notification.expires_at {
                notification.status = PushStatus::Expired;
                return Ok(false);
            }

            // Update status based on response
            match request.response {
                PushResponse::Approve => {
                    notification.status = PushStatus::Approved;
                    let device_id = notification.device_id.clone();
                    (true, Some(device_id))
                }
                PushResponse::Deny => {
                    notification.status = PushStatus::Denied;
                    (false, None)
                }
            }
        };

        // Update last_used on the device if approved
        if let Some(device_id) = device_id {
            let mut enrollments = self.enrollments.write().await;
            if let Some(devices) = enrollments.get_mut(&request.entity_id)
                && let Some(device) = devices.get_mut(&device_id)
            {
                device.last_used = Some(Utc::now());
            }
        }

        Ok(is_approved)
    }

    async fn remove_enrollment(&self, entity_id: Uuid, device_id: &str) -> AuthMethodResult<()> {
        let mut enrollments = self.enrollments.write().await;
        if let Some(devices) = enrollments.get_mut(&entity_id) {
            devices.remove(device_id);
            if devices.is_empty() {
                enrollments.remove(&entity_id);
            }
        }
        Ok(())
    }

    async fn list_devices(&self, entity_id: Uuid) -> AuthMethodResult<Vec<PushDeviceEnrollment>> {
        let enrollments = self.enrollments.read().await;
        Ok(enrollments
            .get(&entity_id)
            .map(|devices| devices.values().cloned().collect())
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_push_enrollment() {
        let service = DefaultPushService::new_mock();
        let entity_id = Uuid::new_v4();

        let enrollment = service
            .enroll_device(
                entity_id,
                "device-123".to_string(),
                "Test Device".to_string(),
                "push-token-abc".to_string(),
                "iOS".to_string(),
            )
            .await
            .unwrap();

        assert_eq!(enrollment.entity_id, entity_id);
        assert_eq!(enrollment.device_id, "device-123");
        assert_eq!(enrollment.platform, "iOS");
    }

    #[tokio::test]
    async fn test_push_notification_flow() {
        let service = DefaultPushService::new_mock();
        let entity_id = Uuid::new_v4();

        // Enroll device first
        service
            .enroll_device(
                entity_id,
                "device-123".to_string(),
                "Test Device".to_string(),
                "push-token-abc".to_string(),
                "iOS".to_string(),
            )
            .await
            .unwrap();

        // Send notification
        let notification = service
            .send_notification(
                entity_id,
                "device-123",
                "Login Request",
                "Approve login?",
                Some("192.168.1.1".to_string()),
                None,
            )
            .await
            .unwrap();

        assert_eq!(notification.status, PushStatus::Pending);

        // Check status
        let status = service
            .get_notification_status(notification.id)
            .await
            .unwrap();
        assert_eq!(status, PushStatus::Pending);

        // Approve the notification
        let result = service
            .validate(PushValidationRequest {
                entity_id,
                notification_id: notification.id,
                response: PushResponse::Approve,
            })
            .await
            .unwrap();

        assert!(result);

        // Verify status changed
        let status = service
            .get_notification_status(notification.id)
            .await
            .unwrap();
        assert_eq!(status, PushStatus::Approved);
    }
}
