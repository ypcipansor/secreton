//! AppRole Definition
//!
//! Defines the structure and configuration of an AppRole

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRole {
    /// Unique identifier for the role
    pub role_id: String,

    /// Policies associated with tokens issued by this role
    pub token_policies: Vec<String>,

    /// TTL for tokens issued by this role (in seconds)
    pub token_ttl: Option<u64>,

    /// Maximum TTL for tokens issued by this role (in seconds)
    pub token_max_ttl: Option<u64>,

    /// TTL for secret IDs generated for this role (in seconds)
    pub secret_id_ttl: Option<u64>,

    /// Maximum number of times a secret ID can be used
    pub secret_id_num_uses: Option<u32>,

    /// Whether to bind secret IDs to the role
    pub bind_secret_id: bool,

    /// CIDR blocks from which authentication is allowed
    pub bound_cidr_list: Option<Vec<String>>,

    /// Additional metadata for the role
    pub metadata: Option<HashMap<String, String>>,

    /// Whether the role is enabled
    pub enabled: bool,

    /// Whether tokens issued by this role are renewable
    pub token_renewable: bool,

    /// Maximum number of tokens that can be issued by this role
    pub token_bound_cidrs: Option<Vec<String>>,

    /// Explicit maximum TTL for tokens
    pub token_explicit_max_ttl: Option<u64>,

    /// Whether tokens should not have a default policy
    pub token_no_default_policy: bool,

    /// Number of uses for tokens issued by this role
    pub token_num_uses: Option<u32>,

    /// Period for tokens issued by this role
    pub token_period: Option<u64>,

    /// Type of token to generate (service, batch, default)
    pub token_type: TokenType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub enum TokenType {
    #[serde(rename = "default")]
    #[default]
    Default,
    #[serde(rename = "service")]
    Service,
    #[serde(rename = "batch")]
    Batch,
}


impl Default for AppRole {
    fn default() -> Self {
        Self {
            role_id: String::new(),
            token_policies: vec!["default".to_string()],
            token_ttl: Some(3600),
            token_max_ttl: Some(86400),
            secret_id_ttl: Some(86400),
            secret_id_num_uses: None,
            bind_secret_id: true,
            bound_cidr_list: None,
            metadata: None,
            enabled: true,
            token_renewable: true,
            token_bound_cidrs: None,
            token_explicit_max_ttl: None,
            token_no_default_policy: false,
            token_num_uses: None,
            token_period: None,
            token_type: TokenType::Default,
        }
    }
}

impl AppRole {
    /// Create a new AppRole with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the role ID
    pub fn with_role_id(mut self, role_id: String) -> Self {
        self.role_id = role_id;
        self
    }

    /// Set token policies
    pub fn with_token_policies(mut self, policies: Vec<String>) -> Self {
        self.token_policies = policies;
        self
    }

    /// Set token TTL
    pub fn with_token_ttl(mut self, ttl: u64) -> Self {
        self.token_ttl = Some(ttl);
        self
    }

    /// Set token max TTL
    pub fn with_token_max_ttl(mut self, ttl: u64) -> Self {
        self.token_max_ttl = Some(ttl);
        self
    }

    /// Set secret ID TTL
    pub fn with_secret_id_ttl(mut self, ttl: u64) -> Self {
        self.secret_id_ttl = Some(ttl);
        self
    }

    /// Set secret ID number of uses
    pub fn with_secret_id_num_uses(mut self, num_uses: u32) -> Self {
        self.secret_id_num_uses = Some(num_uses);
        self
    }

    /// Set whether to bind secret IDs
    pub fn with_bind_secret_id(mut self, bind: bool) -> Self {
        self.bind_secret_id = bind;
        self
    }

    /// Set bound CIDR list
    pub fn with_bound_cidr_list(mut self, cidrs: Vec<String>) -> Self {
        self.bound_cidr_list = Some(cidrs);
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set enabled status
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set token renewable
    pub fn with_token_renewable(mut self, renewable: bool) -> Self {
        self.token_renewable = renewable;
        self
    }

    /// Set token type
    pub fn with_token_type(mut self, token_type: TokenType) -> Self {
        self.token_type = token_type;
        self
    }

    /// Add a policy to the role
    pub fn add_policy(mut self, policy: String) -> Self {
        if !self.token_policies.contains(&policy) {
            self.token_policies.push(policy);
        }
        self
    }

    /// Remove a policy from the role
    pub fn remove_policy(mut self, policy: &str) -> Self {
        self.token_policies.retain(|p| p != policy);
        self
    }

    /// Validate the role configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.role_id.is_empty() {
            return Err("Role ID cannot be empty".to_string());
        }

        if self.token_policies.is_empty() {
            return Err("At least one token policy must be specified".to_string());
        }

        if let (Some(ttl), Some(max_ttl)) = (self.token_ttl, self.token_max_ttl) {
            if ttl > max_ttl {
                return Err("Token TTL cannot be greater than max TTL".to_string());
            }
        }

        if let Some(secret_id_ttl) = self.secret_id_ttl {
            if secret_id_ttl == 0 {
                return Err("Secret ID TTL must be greater than 0".to_string());
            }
        }

        if let Some(num_uses) = self.secret_id_num_uses {
            if num_uses == 0 {
                return Err("Secret ID number of uses must be greater than 0".to_string());
            }
        }

        if let Some(cidrs) = &self.bound_cidr_list {
            for cidr in cidrs {
                if cidr.is_empty() {
                    return Err("CIDR blocks cannot be empty".to_string());
                }
                // TODO: Add proper CIDR validation
            }
        }

        Ok(())
    }

    /// Check if authentication is allowed from the given IP address
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        match &self.bound_cidr_list {
            Some(cidrs) => {
                cidrs.iter().any(|cidr| {
                    if cidr.contains('/') {
                        // Handle CIDR notation
                        Self::ip_in_cidr(ip, cidr)
                    } else {
                        // Handle individual IP
                        cidr == ip
                    }
                })
            }
            None => true, // No restrictions
        }
    }

    /// Check if an IP address is within a CIDR range
    fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let network_ip = parts[0];
        let prefix_len: u32 = match parts[1].parse() {
            Ok(len) => len,
            Err(_) => return false,
        };

        // Simple IPv4 CIDR matching
        let ip_bytes = Self::ip_to_u32(ip);
        let network_bytes = Self::ip_to_u32(network_ip);

        match (ip_bytes, network_bytes) {
            (Some(ip_val), Some(net_val)) => {
                let mask = (!0u32) << (32 - prefix_len);
                (ip_val & mask) == (net_val & mask)
            }
            _ => false,
        }
    }

    /// Convert IPv4 address string to u32
    fn ip_to_u32(ip: &str) -> Option<u32> {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return None;
        }

        let mut result = 0u32;
        for (i, part) in parts.iter().enumerate() {
            let byte: u8 = part.parse().ok()?;
            result |= (byte as u32) << (8 * (3 - i));
        }
        Some(result)
    }

    /// Get effective token TTL considering all limits
    pub fn effective_token_ttl(&self) -> u64 {
        let default_ttl = self.token_ttl.unwrap_or(3600);

        match (self.token_max_ttl, self.token_explicit_max_ttl) {
            (Some(max_ttl), Some(explicit_max)) => default_ttl.min(max_ttl).min(explicit_max),
            (Some(max_ttl), None) => default_ttl.min(max_ttl),
            (None, Some(explicit_max)) => default_ttl.min(explicit_max),
            (None, None) => default_ttl,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_approle() {
        let role = AppRole::default();
        assert_eq!(role.token_policies, vec!["default"]);
        assert_eq!(role.token_ttl, Some(3600));
        assert_eq!(role.token_max_ttl, Some(86400));
        assert!(role.bind_secret_id);
        assert!(role.enabled);
        assert!(role.token_renewable);
    }

    #[test]
    fn test_approle_builder() {
        let role = AppRole::new()
            .with_token_policies(vec!["app-policy".to_string(), "read-policy".to_string()])
            .with_token_ttl(1800)
            .with_secret_id_ttl(7200)
            .with_bind_secret_id(false);

        assert_eq!(role.token_policies, vec!["app-policy", "read-policy"]);
        assert_eq!(role.token_ttl, Some(1800));
        assert_eq!(role.secret_id_ttl, Some(7200));
        assert!(!role.bind_secret_id);
    }

    #[test]
    fn test_add_remove_policy() {
        let mut role = AppRole::new();
        role = role.add_policy("new-policy".to_string());
        assert!(role.token_policies.contains(&"new-policy".to_string()));

        role = role.remove_policy("default");
        assert!(!role.token_policies.contains(&"default".to_string()));
    }

    #[test]
    fn test_role_validation() {
        let valid_role = AppRole::new().with_role_id("test-role".to_string());
        assert!(valid_role.validate().is_ok());

        let invalid_role = AppRole {
            role_id: String::new(),
            ..Default::default()
        };
        assert!(invalid_role.validate().is_err());

        let invalid_ttl_role = AppRole {
            role_id: "test".to_string(),
            token_ttl: Some(7200),
            token_max_ttl: Some(3600),
            ..Default::default()
        };
        assert!(invalid_ttl_role.validate().is_err());
    }

    #[test]
    fn test_effective_token_ttl() {
        let role = AppRole {
            token_ttl: Some(3600),
            token_max_ttl: Some(7200),
            token_explicit_max_ttl: Some(1800),
            ..Default::default()
        };

        assert_eq!(role.effective_token_ttl(), 1800); // Should use the minimum

        let role2 = AppRole {
            token_ttl: Some(1800),
            token_max_ttl: Some(7200),
            token_explicit_max_ttl: None,
            ..Default::default()
        };

        assert_eq!(role2.effective_token_ttl(), 1800);
    }

    #[test]
    fn test_ip_allowed() {
        let role = AppRole {
            bound_cidr_list: Some(vec!["192.168.1.0/24".to_string(), "10.0.0.1".to_string()]),
            ..Default::default()
        };

        assert!(role.is_ip_allowed("192.168.1.100"));
        assert!(role.is_ip_allowed("10.0.0.1"));
        assert!(!role.is_ip_allowed("172.16.0.1"));

        let unrestricted_role = AppRole::default();
        assert!(unrestricted_role.is_ip_allowed("any.ip.address"));
    }
}
