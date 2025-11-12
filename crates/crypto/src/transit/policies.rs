//! Transit engine policies and security controls

// CLEANUP: Removed unused imports
// use crate::error::{CryptoError, CryptoResult};
use crate::transit::KeyType;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Global policies for the transit engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitPolicies {
    /// Maximum number of keys allowed
    pub max_keys: usize,
    /// Maximum random bytes that can be generated in one request
    pub max_random_bytes: usize,
    /// Key rotation policies
    pub rotation_policy: RotationPolicy,
    /// Access control policies
    pub access_control: AccessControlPolicy,
    /// Audit policies
    pub audit_policy: AuditPolicy,
    /// Key usage policies
    pub key_usage_policy: KeyUsagePolicy,
    /// Performance limits
    pub performance_limits: PerformanceLimits,
}

impl Default for TransitPolicies {
    fn default() -> Self {
        Self {
            max_keys: 10000,
            max_random_bytes: 1024 * 1024, // 1MB
            rotation_policy: RotationPolicy::default(),
            access_control: AccessControlPolicy::default(),
            audit_policy: AuditPolicy::default(),
            key_usage_policy: KeyUsagePolicy::default(),
            performance_limits: PerformanceLimits::default(),
        }
    }
}

/// Key rotation policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Automatic rotation interval (None = manual only)
    pub auto_rotation_interval: Option<Duration>,
    /// Maximum key age before forced rotation
    pub max_key_age: Option<Duration>,
    /// Minimum versions to keep after rotation
    pub min_versions_to_keep: u32,
    /// Maximum versions to keep (oldest deleted first)
    pub max_versions_to_keep: u32,
    /// Keys that require automatic rotation
    pub auto_rotate_keys: HashSet<String>,
    /// Keys exempt from rotation policies
    pub rotation_exempt_keys: HashSet<String>,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            auto_rotation_interval: Some(Duration::days(90)),
            max_key_age: Some(Duration::days(365)),
            min_versions_to_keep: 1,
            max_versions_to_keep: 10,
            auto_rotate_keys: HashSet::new(),
            rotation_exempt_keys: HashSet::new(),
        }
    }
}

/// Access control policies
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessControlPolicy {
    /// Role-based access control
    pub rbac: RoleBasedAccessControl,
    /// IP address restrictions
    pub ip_restrictions: IpRestrictions,
    /// Time-based access controls
    pub time_restrictions: TimeRestrictions,
    /// Rate limiting policies
    pub rate_limiting: RateLimitingPolicy,
}

/// Role-based access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleBasedAccessControl {
    /// Available roles and their permissions
    pub roles: HashMap<String, Role>,
    /// User role assignments
    pub user_roles: HashMap<String, Vec<String>>,
    /// Default role for new users
    pub default_role: String,
}

impl Default for RoleBasedAccessControl {
    fn default() -> Self {
        let mut roles = HashMap::new();

        // Define default roles
        roles.insert(
            "admin".to_string(),
            Role {
                name: "admin".to_string(),
                permissions: vec![
                    Permission::CreateKey,
                    Permission::DeleteKey,
                    Permission::RotateKey,
                    Permission::Encrypt,
                    Permission::Decrypt,
                    Permission::Sign,
                    Permission::Verify,
                    Permission::DeriveKey,
                    Permission::GenerateRandom,
                    Permission::ManagePolicies,
                ],
                key_restrictions: KeyRestrictions::default(),
            },
        );

        roles.insert(
            "operator".to_string(),
            Role {
                name: "operator".to_string(),
                permissions: vec![
                    Permission::CreateKey,
                    Permission::RotateKey,
                    Permission::Encrypt,
                    Permission::Decrypt,
                    Permission::Sign,
                    Permission::Verify,
                    Permission::DeriveKey,
                    Permission::GenerateRandom,
                ],
                key_restrictions: KeyRestrictions::default(),
            },
        );

        roles.insert(
            "user".to_string(),
            Role {
                name: "user".to_string(),
                permissions: vec![
                    Permission::Encrypt,
                    Permission::Decrypt,
                    Permission::Sign,
                    Permission::Verify,
                    Permission::GenerateRandom,
                ],
                key_restrictions: KeyRestrictions::default(),
            },
        );

        Self {
            roles,
            user_roles: HashMap::new(),
            default_role: "user".to_string(),
        }
    }
}

/// User role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<Permission>,
    pub key_restrictions: KeyRestrictions,
}

/// Available permissions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    CreateKey,
    DeleteKey,
    RotateKey,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    DeriveKey,
    GenerateRandom,
    ManagePolicies,
    ViewAuditLogs,
}

/// Key access restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRestrictions {
    /// Allowed key types
    pub allowed_key_types: Option<Vec<KeyType>>,
    /// Allowed key name patterns (regex)
    pub allowed_key_patterns: Vec<String>,
    /// Denied key name patterns (regex)
    pub denied_key_patterns: Vec<String>,
    /// Maximum data size for operations (bytes)
    pub max_data_size: Option<usize>,
}

impl Default for KeyRestrictions {
    fn default() -> Self {
        Self {
            allowed_key_types: None,                      // All types allowed by default
            allowed_key_patterns: vec![".*".to_string()], // All names allowed by default
            denied_key_patterns: Vec::new(),
            max_data_size: None, // No limit by default
        }
    }
}

/// IP address restrictions
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpRestrictions {
    /// Allowed IP addresses/ranges (CIDR notation)
    pub allowed_ips: Vec<String>,
    /// Denied IP addresses/ranges (CIDR notation)
    pub denied_ips: Vec<String>,
    /// Enable IP restriction enforcement
    pub enabled: bool,
}

/// Time-based access restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestrictions {
    /// Allowed time windows (day of week, hour range)
    pub allowed_time_windows: Vec<TimeWindow>,
    /// Timezone for time calculations
    pub timezone: String,
    /// Enable time restriction enforcement
    pub enabled: bool,
}

impl Default for TimeRestrictions {
    fn default() -> Self {
        Self {
            allowed_time_windows: vec![TimeWindow::always()],
            timezone: "UTC".to_string(),
            enabled: false,
        }
    }
}

/// Time window definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Days of week (0 = Sunday, 6 = Saturday)
    pub days: Vec<u8>,
    /// Start hour (0-23)
    pub start_hour: u8,
    /// End hour (0-23)
    pub end_hour: u8,
}

impl TimeWindow {
    /// Create an "always allowed" time window
    pub fn always() -> Self {
        Self {
            days: vec![0, 1, 2, 3, 4, 5, 6], // All days
            start_hour: 0,
            end_hour: 23,
        }
    }

    /// Create business hours time window (Mon-Fri, 9AM-5PM)
    pub fn business_hours() -> Self {
        Self {
            days: vec![1, 2, 3, 4, 5], // Mon-Fri
            start_hour: 9,
            end_hour: 17,
        }
    }
}

/// Rate limiting policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingPolicy {
    /// Maximum operations per minute per user
    pub max_operations_per_minute: u32,
    /// Maximum operations per hour per user
    pub max_operations_per_hour: u32,
    /// Maximum operations per day per user
    pub max_operations_per_day: u32,
    /// Maximum concurrent operations per user
    pub max_concurrent_operations: u32,
    /// Enable rate limiting
    pub enabled: bool,
}

impl Default for RateLimitingPolicy {
    fn default() -> Self {
        Self {
            max_operations_per_minute: 100,
            max_operations_per_hour: 1000,
            max_operations_per_day: 10000,
            max_concurrent_operations: 10,
            enabled: true,
        }
    }
}

/// Audit policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicy {
    /// Enable audit logging
    pub enabled: bool,
    /// Log all operations (not just sensitive ones)
    pub log_all_operations: bool,
    /// Include request/response data in logs
    pub include_data: bool,
    /// Maximum log retention period
    pub retention_period: Duration,
    /// Audit log destinations
    pub destinations: Vec<AuditDestination>,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            log_all_operations: false,
            include_data: false,
            retention_period: Duration::days(90),
            destinations: vec![AuditDestination::File {
                path: "/var/log/secreton/transit-audit.log".to_string(),
            }],
        }
    }
}

/// Audit log destinations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditDestination {
    File {
        path: String,
    },
    Syslog {
        facility: String,
    },
    Database {
        connection_string: String,
    },
    Webhook {
        url: String,
        headers: HashMap<String, String>,
    },
}

/// Key usage policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUsagePolicy {
    /// Require minimum key strength
    pub minimum_key_strength: KeyStrength,
    /// Allowed algorithms for new keys
    pub allowed_algorithms: Vec<KeyType>,
    /// Require key usage restrictions
    pub require_usage_restrictions: bool,
    /// Default key options for new keys
    pub default_key_options: DefaultKeyOptions,
}

impl Default for KeyUsagePolicy {
    fn default() -> Self {
        Self {
            minimum_key_strength: KeyStrength::High,
            allowed_algorithms: vec![
                KeyType::Aes256Gcm,
                KeyType::ChaCha20Poly1305,
                KeyType::XChaCha20Poly1305,
                KeyType::EcdsaP256,
                KeyType::Ed25519,
            ],
            require_usage_restrictions: false,
            default_key_options: DefaultKeyOptions::default(),
        }
    }
}

/// Key strength levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KeyStrength {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl KeyStrength {
    /// Get minimum key strength for a key type
    pub fn for_key_type(key_type: &KeyType) -> Self {
        match key_type {
            KeyType::Aes256Gcm => KeyStrength::High,
            KeyType::ChaCha20Poly1305 => KeyStrength::High,
            KeyType::XChaCha20Poly1305 => KeyStrength::High,
            KeyType::EcdsaP256 => KeyStrength::High,
            KeyType::EcdsaSecp256k1 => KeyStrength::High,
            // Ed25519 is considered very high security due to its resistance to side-channel attacks
            KeyType::Ed25519 => KeyStrength::VeryHigh,
            KeyType::X25519 => KeyStrength::High,
            KeyType::Rsa(size) => {
                if *size >= 4096 {
                    KeyStrength::VeryHigh
                } else if *size >= 2048 {
                    KeyStrength::High
                } else {
                    KeyStrength::Medium
                }
            }
        }
    }
}

/// Default options for new keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultKeyOptions {
    pub exportable: bool,
    pub allow_plaintext_backup: bool,
    pub min_decryption_version: u32,
    pub auto_rotate: bool,
    pub rotation_interval: Option<Duration>,
}

impl Default for DefaultKeyOptions {
    fn default() -> Self {
        Self {
            exportable: false,
            allow_plaintext_backup: false,
            min_decryption_version: 1,
            auto_rotate: false,
            rotation_interval: Some(Duration::days(90)),
        }
    }
}

/// Performance limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceLimits {
    /// Maximum concurrent operations
    pub max_concurrent_operations: usize,
    /// Maximum operation timeout
    pub max_operation_timeout: Duration,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Maximum key cache size
    pub max_key_cache_size: usize,
    /// Enable performance monitoring
    pub performance_monitoring: bool,
}

impl Default for PerformanceLimits {
    fn default() -> Self {
        Self {
            max_concurrent_operations: 1000,
            max_operation_timeout: Duration::seconds(30),
            max_batch_size: 1000,
            max_key_cache_size: 10000,
            performance_monitoring: true,
        }
    }
}

/// Policy enforcement engine
#[derive(Debug)]
pub struct PolicyEngine {
    policies: TransitPolicies,
    rate_limiters: HashMap<String, RateLimiter>,
}

impl PolicyEngine {
    /// Create new policy engine
    pub fn new(policies: TransitPolicies) -> Self {
        Self {
            policies,
            rate_limiters: HashMap::new(),
        }
    }

    /// Check if user has permission for operation
    pub fn check_permission(&self, user: &str, permission: Permission) -> bool {
        if let Some(roles) = self.policies.access_control.rbac.user_roles.get(user) {
            for role_name in roles {
                if let Some(role) = self.policies.access_control.rbac.roles.get(role_name) {
                    if role.permissions.contains(&permission) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if key type is allowed for user
    pub fn check_key_type_allowed(&self, user: &str, key_type: &KeyType) -> bool {
        // Check global policy
        if !self
            .policies
            .key_usage_policy
            .allowed_algorithms
            .contains(key_type)
        {
            return false;
        }

        // Check user role restrictions
        if let Some(roles) = self.policies.access_control.rbac.user_roles.get(user) {
            for role_name in roles {
                if let Some(role) = self.policies.access_control.rbac.roles.get(role_name) {
                    if let Some(allowed_types) = &role.key_restrictions.allowed_key_types {
                        return allowed_types.contains(key_type);
                    }
                }
            }
        }

        true // Default allow if no restrictions
    }

    /// Check if key strength meets minimum requirements
    pub fn check_key_strength(&self, key_type: &KeyType) -> bool {
        let key_strength = KeyStrength::for_key_type(key_type);
        key_strength >= self.policies.key_usage_policy.minimum_key_strength
    }

    /// Check rate limits for user
    pub fn check_rate_limit(&mut self, user: &str) -> bool {
        if !self.policies.access_control.rate_limiting.enabled {
            return true;
        }

        let rate_limiter = self
            .rate_limiters
            .entry(user.to_string())
            .or_insert_with(|| RateLimiter::new(&self.policies.access_control.rate_limiting));

        rate_limiter.check_limit()
    }

    /// Update policies
    pub fn update_policies(&mut self, policies: TransitPolicies) {
        self.policies = policies;
        // Clear rate limiters to apply new limits
        self.rate_limiters.clear();
    }

    /// Get current policies
    pub fn get_policies(&self) -> &TransitPolicies {
        &self.policies
    }
}

/// Simple rate limiter implementation
#[derive(Debug)]
struct RateLimiter {
    policy: RateLimitingPolicy,
    minute_counter: u32,
    hour_counter: u32,
    day_counter: u32,
    last_minute: DateTime<Utc>,
    last_hour: DateTime<Utc>,
    last_day: DateTime<Utc>,
}

impl RateLimiter {
    fn new(policy: &RateLimitingPolicy) -> Self {
        let now = Utc::now();
        Self {
            policy: policy.clone(),
            minute_counter: 0,
            hour_counter: 0,
            day_counter: 0,
            last_minute: now,
            last_hour: now,
            last_day: now,
        }
    }

    fn check_limit(&mut self) -> bool {
        let now = Utc::now();

        // Reset counters if time periods have passed
        if now.signed_duration_since(self.last_minute).num_minutes() >= 1 {
            self.minute_counter = 0;
            self.last_minute = now;
        }

        if now.signed_duration_since(self.last_hour).num_hours() >= 1 {
            self.hour_counter = 0;
            self.last_hour = now;
        }

        if now.signed_duration_since(self.last_day).num_days() >= 1 {
            self.day_counter = 0;
            self.last_day = now;
        }

        // Check limits
        if self.minute_counter >= self.policy.max_operations_per_minute {
            return false;
        }

        if self.hour_counter >= self.policy.max_operations_per_hour {
            return false;
        }

        if self.day_counter >= self.policy.max_operations_per_day {
            return false;
        }

        // Increment counters
        self.minute_counter += 1;
        self.hour_counter += 1;
        self.day_counter += 1;

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policies() {
        let policies = TransitPolicies::default();
        assert_eq!(policies.max_keys, 10000);
        assert_eq!(policies.max_random_bytes, 1024 * 1024);
        assert!(policies.rotation_policy.auto_rotation_interval.is_some());
    }

    #[test]
    fn test_key_strength() {
        assert_eq!(
            KeyStrength::for_key_type(&KeyType::Aes256Gcm),
            KeyStrength::High
        );
        assert_eq!(
            KeyStrength::for_key_type(&KeyType::ChaCha20Poly1305),
            KeyStrength::High
        );
        assert_eq!(
            KeyStrength::for_key_type(&KeyType::Ed25519),
            KeyStrength::VeryHigh
        );
    }

    #[test]
    fn test_policy_engine() {
        let policies = TransitPolicies::default();
        let engine = PolicyEngine::new(policies);

        // Test key strength check
        assert!(engine.check_key_strength(&KeyType::Aes256Gcm));
        assert!(engine.check_key_strength(&KeyType::Ed25519));
    }

    #[test]
    fn test_time_window() {
        let always = TimeWindow::always();
        assert_eq!(always.days.len(), 7);

        let business = TimeWindow::business_hours();
        assert_eq!(business.days.len(), 5);
        assert_eq!(business.start_hour, 9);
        assert_eq!(business.end_hour, 17);
    }
}
