//! Database Credentials and Lease Management
//! 
//! Defines credential structures and lease management for database secrets.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Database credentials response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseCredentials {
    /// Database username
    pub username: String,

    /// Database password (for password credentials)
    pub password: String,

    /// Type of credential
    pub credential_type: CredentialType,

    /// Lease ID (for dynamic credentials)
    pub lease_id: Option<String>,

    /// Lease duration in seconds (for dynamic credentials)
    pub lease_duration: Option<u64>,

    /// Whether the lease is renewable
    pub renewable: Option<bool>,

    /// Last vault rotation timestamp (for static credentials)
    pub last_vault_rotation: Option<u64>,

    /// Rotation period in seconds (for static credentials)
    pub rotation_period: Option<u64>,

    /// TTL in seconds until next rotation/expiration
    pub ttl: Option<u64>,
}

impl DatabaseCredentials {
    /// Create new dynamic credentials
    pub fn new_dynamic(
        username: String,
        password: String,
        lease_id: String,
        lease_duration: Duration,
        renewable: bool,
    ) -> Self {
        Self {
            username,
            password,
            credential_type: CredentialType::Password,
            lease_id: Some(lease_id),
            lease_duration: Some(lease_duration.as_secs()),
            renewable: Some(renewable),
            last_vault_rotation: None,
            rotation_period: None,
            ttl: Some(lease_duration.as_secs()),
        }
    }

    /// Create new static credentials
    pub fn new_static(
        username: String,
        password: String,
        last_rotation: Option<u64>,
        rotation_period: Duration,
    ) -> Self {
        // Calculate TTL until next rotation
        let ttl = match last_rotation {
            Some(last) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let next_rotation = last + rotation_period.as_secs();
                if next_rotation > now {
                    Some(next_rotation - now)
                } else {
                    Some(0) // Overdue for rotation
                }
            }
            None => Some(0), // Never rotated
        };

        Self {
            username,
            password,
            credential_type: CredentialType::Password,
            lease_id: None,
            lease_duration: None,
            renewable: None,
            last_vault_rotation: last_rotation,
            rotation_period: Some(rotation_period.as_secs()),
            ttl,
        }
    }

    /// Check if credentials are dynamic
    pub fn is_dynamic(&self) -> bool {
        self.lease_id.is_some()
    }

    /// Check if credentials are static
    pub fn is_static(&self) -> bool {
        self.lease_id.is_none() && self.last_vault_rotation.is_some()
    }

    /// Check if credentials are renewable
    pub fn is_renewable(&self) -> bool {
        self.renewable.unwrap_or(false)
    }

    /// Get remaining TTL in seconds
    pub fn remaining_ttl(&self) -> Option<u64> {
        self.ttl
    }

    /// Check if credentials are expired
    pub fn is_expired(&self) -> bool {
        match self.ttl {
            Some(ttl) => ttl == 0,
            None => false, // No TTL means no expiration
        }
    }
}

/// Credential type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CredentialType {
    /// Password-based authentication
    Password,
    /// Client certificate authentication
    ClientCertificate,
}

impl Default for CredentialType {
    fn default() -> Self {
        CredentialType::Password
    }
}

/// Lease information for dynamic credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// Unique lease identifier
    pub lease_id: String,

    /// Lease duration
    pub duration: Duration,

    /// Whether the lease can be renewed
    pub renewable: bool,

    /// Database username associated with lease
    pub username: String,

    /// Role name that created the lease
    pub role_name: String,

    /// Lease creation time
    pub created_at: SystemTime,

    /// Lease expiration time
    pub expires_at: SystemTime,

    /// Number of times lease has been renewed
    pub renew_count: u32,

    /// Maximum number of renewals allowed
    pub max_renewals: Option<u32>,
}

impl Lease {
    /// Create new lease
    pub fn new(
        lease_id: String,
        duration: Duration,
        renewable: bool,
        username: String,
        role_name: String,
    ) -> Self {
        let created_at = SystemTime::now();
        let expires_at = created_at + duration;

        Self {
            lease_id,
            duration,
            renewable,
            username,
            role_name,
            created_at,
            expires_at,
            renew_count: 0,
            max_renewals: Some(5), // Default: allow 5 renewals
        }
    }

    /// Check if lease is expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    /// Check if lease can be renewed
    pub fn can_renew(&self) -> bool {
        self.renewable && 
        !self.is_expired() &&
        self.max_renewals.map_or(true, |max| self.renew_count < max)
    }

    /// Renew the lease
    pub fn renew(&mut self, extension: Duration) -> Result<(), String> {
        if !self.can_renew() {
            return Err("Lease cannot be renewed".to_string());
        }

        self.expires_at = SystemTime::now() + extension;
        self.renew_count += 1;
        self.duration = extension;

        Ok(())
    }

    /// Get remaining lease time
    pub fn remaining_time(&self) -> Duration {
        self.expires_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::from_secs(0))
    }

    /// Get remaining time in seconds
    pub fn remaining_seconds(&self) -> u64 {
        self.remaining_time().as_secs()
    }

    /// Generate new lease ID
    pub fn generate_lease_id(prefix: &str) -> String {
        format!("{}/{}", prefix, Uuid::new_v4())
    }
}

/// Lease renewal request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRenewalRequest {
    /// Lease ID to renew
    pub lease_id: String,

    /// Requested lease increment (optional)
    pub increment: Option<Duration>,
}

/// Lease renewal response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRenewalResponse {
    /// Renewed lease ID
    pub lease_id: String,

    /// New lease duration
    pub lease_duration: u64,

    /// Whether the lease is renewable
    pub renewable: bool,

    /// New expiration time (Unix timestamp)
    pub expires_at: u64,
}

impl LeaseRenewalResponse {
    /// Create lease renewal response from lease
    pub fn from_lease(lease: &Lease) -> Self {
        Self {
            lease_id: lease.lease_id.clone(),
            lease_duration: lease.duration.as_secs(),
            renewable: lease.renewable,
            expires_at: lease.expires_at
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }
}

/// Credential revocation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// Lease ID to revoke
    pub lease_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_credentials_creation() {
        let creds = DatabaseCredentials::new_dynamic(
            "test_user".to_string(),
            "password123".to_string(),
            "database/creds/test-role/uuid".to_string(),
            Duration::from_secs(3600),
            true,
        );

        assert_eq!(creds.username, "test_user");
        assert_eq!(creds.password, "password123");
        assert!(creds.is_dynamic());
        assert!(!creds.is_static());
        assert!(creds.is_renewable());
        assert_eq!(creds.remaining_ttl(), Some(3600));
        assert!(!creds.is_expired());
    }

    #[test]
    fn test_static_credentials_creation() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let creds = DatabaseCredentials::new_static(
            "static_user".to_string(),
            "password456".to_string(),
            Some(now - 3600), // Rotated 1 hour ago
            Duration::from_secs(86400), // 24 hour rotation period
        );

        assert_eq!(creds.username, "static_user");
        assert_eq!(creds.password, "password456");
        assert!(!creds.is_dynamic());
        assert!(creds.is_static());
        assert!(!creds.is_renewable());
        assert!(creds.remaining_ttl().unwrap() > 82000); // Should be ~23 hours left
    }

    #[test]
    fn test_lease_creation() {
        let lease = Lease::new(
            "database/creds/test-role/uuid".to_string(),
            Duration::from_secs(3600),
            true,
            "test_user".to_string(),
            "test-role".to_string(),
        );

        assert_eq!(lease.lease_id, "database/creds/test-role/uuid");
        assert_eq!(lease.duration, Duration::from_secs(3600));
        assert!(lease.renewable);
        assert_eq!(lease.username, "test_user");
        assert_eq!(lease.role_name, "test-role");
        assert!(!lease.is_expired());
        assert!(lease.can_renew());
        assert_eq!(lease.renew_count, 0);
    }

    #[test]
    fn test_lease_renewal() {
        let mut lease = Lease::new(
            "test-lease".to_string(),
            Duration::from_secs(3600),
            true,
            "test_user".to_string(),
            "test-role".to_string(),
        );

        // Should be able to renew
        assert!(lease.can_renew());
        
        // Renew the lease
        let renewal_result = lease.renew(Duration::from_secs(7200));
        assert!(renewal_result.is_ok());
        assert_eq!(lease.renew_count, 1);
        assert_eq!(lease.duration, Duration::from_secs(7200));

        // After max renewals, should not be able to renew
        lease.renew_count = 5; // Set to max
        assert!(!lease.can_renew());
        
        let renewal_result = lease.renew(Duration::from_secs(3600));
        assert!(renewal_result.is_err());
    }

    #[test]
    fn test_lease_expiration() {
        let mut lease = Lease::new(
            "test-lease".to_string(),
            Duration::from_secs(1),
            true,
            "test_user".to_string(),
            "test-role".to_string(),
        );

        // Should not be expired immediately
        assert!(!lease.is_expired());

        // Manually set expiration to past
        lease.expires_at = SystemTime::now() - Duration::from_secs(1);
        assert!(lease.is_expired());
        assert!(!lease.can_renew()); // Expired leases cannot be renewed
    }

    #[test]
    fn test_lease_id_generation() {
        let lease_id1 = Lease::generate_lease_id("database/creds/test-role");
        let lease_id2 = Lease::generate_lease_id("database/creds/test-role");

        assert!(lease_id1.starts_with("database/creds/test-role/"));
        assert!(lease_id2.starts_with("database/creds/test-role/"));
        assert_ne!(lease_id1, lease_id2); // Should be different UUIDs
    }

    #[test]
    fn test_credential_types() {
        let password_creds = DatabaseCredentials {
            username: "user".to_string(),
            password: "pass".to_string(),
            credential_type: CredentialType::Password,
            lease_id: None,
            lease_duration: None,
            renewable: None,
            last_vault_rotation: None,
            rotation_period: None,
            ttl: None,
        };

        assert_eq!(password_creds.credential_type, CredentialType::Password);

        let cert_creds = DatabaseCredentials {
            credential_type: CredentialType::ClientCertificate,
            ..password_creds
        };

        assert_eq!(cert_creds.credential_type, CredentialType::ClientCertificate);
    }

    #[test]
    fn test_lease_renewal_response() {
        let lease = Lease::new(
            "test-lease".to_string(),
            Duration::from_secs(3600),
            true,
            "test_user".to_string(),
            "test-role".to_string(),
        );

        let response = LeaseRenewalResponse::from_lease(&lease);

        assert_eq!(response.lease_id, "test-lease");
        assert_eq!(response.lease_duration, 3600);
        assert!(response.renewable);
        assert!(response.expires_at > 0);
    }
}
