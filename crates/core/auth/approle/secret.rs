//! Secret ID Management for AppRole
//! 
//! Handles secret ID generation, validation, and lifecycle management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretId {
    /// Hashed secret ID for secure storage
    pub secret_id_hash: String,
    
    /// Unique accessor for the secret ID
    pub accessor: String,
    
    /// Role name this secret ID belongs to
    pub role_name: String,
    
    /// Metadata associated with the secret ID
    pub metadata: HashMap<String, String>,
    
    /// Creation timestamp (Unix timestamp)
    pub creation_time: u64,
    
    /// Expiration timestamp (Unix timestamp), None for no expiration
    pub expiration_time: Option<u64>,
    
    /// Maximum number of uses, None for unlimited
    pub num_uses: Option<u32>,
    
    /// Current usage count
    pub used_count: u32,
    
    /// CIDR blocks from which this secret ID can be used
    pub cidr_list: Option<Vec<String>>,
    
    /// Whether this secret ID is currently active
    pub active: bool,
    
    /// Token bound to this secret ID (if any)
    pub token_bound_cidrs: Option<Vec<String>>,
}

impl SecretId {
    /// Create a new SecretId
    pub fn new(
        secret_id_hash: String,
        accessor: String,
        role_name: String,
        metadata: HashMap<String, String>,
        expiration_time: Option<u64>,
        num_uses: Option<u32>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            secret_id_hash,
            accessor,
            role_name,
            metadata,
            creation_time: now,
            expiration_time,
            num_uses,
            used_count: 0,
            cidr_list: None,
            active: true,
            token_bound_cidrs: None,
        }
    }
    
    /// Check if the secret ID is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expiration) = self.expiration_time {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now > expiration
        } else {
            false
        }
    }
    
    /// Check if the secret ID has exceeded usage limits
    pub fn is_usage_exceeded(&self) -> bool {
        if let Some(max_uses) = self.num_uses {
            self.used_count >= max_uses
        } else {
            false
        }
    }
    
    /// Check if the secret ID is valid for use
    pub fn is_valid(&self) -> bool {
        self.active && !self.is_expired() && !self.is_usage_exceeded()
    }
    
    /// Increment the usage count
    pub fn increment_usage(&mut self) -> Result<(), String> {
        if !self.is_valid() {
            return Err("Secret ID is not valid for use".to_string());
        }
        
        self.used_count += 1;
        Ok(())
    }
    
    /// Deactivate the secret ID
    pub fn deactivate(&mut self) {
        self.active = false;
    }
    
    /// Check if authentication is allowed from the given IP address
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        match &self.cidr_list {
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
    
    /// Get remaining uses for this secret ID
    pub fn remaining_uses(&self) -> Option<u32> {
        self.num_uses.map(|max| max.saturating_sub(self.used_count))
    }
    
    /// Get time remaining until expiration (in seconds)
    pub fn time_until_expiration(&self) -> Option<u64> {
        self.expiration_time.map(|expiration| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            expiration.saturating_sub(now)
        })
    }
    
    /// Convert to a response format (without sensitive data)
    pub fn to_response(&self) -> SecretIdResponse {
        SecretIdResponse {
            accessor: self.accessor.clone(),
            role_name: self.role_name.clone(),
            metadata: self.metadata.clone(),
            creation_time: self.creation_time,
            expiration_time: self.expiration_time,
            num_uses: self.num_uses,
            used_count: self.used_count,
            active: self.active,
            remaining_uses: self.remaining_uses(),
            time_until_expiration: self.time_until_expiration(),
        }
    }
    
    /// Create a secret ID with CIDR restrictions
    pub fn with_cidr_list(mut self, cidrs: Vec<String>) -> Self {
        self.cidr_list = Some(cidrs);
        self
    }
    
    /// Create a secret ID with token bound CIDRs
    pub fn with_token_bound_cidrs(mut self, cidrs: Vec<String>) -> Self {
        self.token_bound_cidrs = Some(cidrs);
        self
    }
    
    /// Validate the secret ID configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.accessor.is_empty() {
            return Err("Secret ID accessor cannot be empty".to_string());
        }
        
        if self.role_name.is_empty() {
            return Err("Role name cannot be empty".to_string());
        }
        
        if let Some(expiration) = self.expiration_time {
            if expiration <= self.creation_time {
                return Err("Expiration time must be after creation time".to_string());
            }
        }
        
        if let Some(num_uses) = self.num_uses {
            if num_uses == 0 {
                return Err("Number of uses must be greater than 0".to_string());
            }
        }
        
        if let Some(cidrs) = &self.cidr_list {
            for cidr in cidrs {
                if cidr.is_empty() {
                    return Err("CIDR blocks cannot be empty".to_string());
                }
                // TODO: Add proper CIDR validation
            }
        }
        
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretIdResponse {
    pub accessor: String,
    pub role_name: String,
    pub metadata: HashMap<String, String>,
    pub creation_time: u64,
    pub expiration_time: Option<u64>,
    pub num_uses: Option<u32>,
    pub used_count: u32,
    pub active: bool,
    pub remaining_uses: Option<u32>,
    pub time_until_expiration: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretIdGenerateRequest {
    pub metadata: Option<HashMap<String, String>>,
    pub cidr_list: Option<Vec<String>>,
    pub token_bound_cidrs: Option<Vec<String>>,
    pub num_uses: Option<u32>,
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretIdGenerateResponse {
    pub secret_id: String,
    pub secret_id_accessor: String,
    pub secret_id_ttl: Option<u64>,
    pub secret_id_num_uses: Option<u32>,
}

impl Default for SecretIdGenerateRequest {
    fn default() -> Self {
        Self {
            metadata: None,
            cidr_list: None,
            token_bound_cidrs: None,
            num_uses: None,
            ttl: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_id_creation() {
        let secret_id = SecretId::new(
            "hashed_secret".to_string(),
            "accessor_123".to_string(),
            "test_role".to_string(),
            HashMap::new(),
            Some(1234567890),
            Some(10),
        );
        
        assert_eq!(secret_id.accessor, "accessor_123");
        assert_eq!(secret_id.role_name, "test_role");
        assert_eq!(secret_id.expiration_time, Some(1234567890));
        assert_eq!(secret_id.num_uses, Some(10));
        assert_eq!(secret_id.used_count, 0);
        assert!(secret_id.active);
    }

    #[test]
    fn test_secret_id_expiration() {
        let expired_secret = SecretId::new(
            "hash".to_string(),
            "accessor".to_string(),
            "role".to_string(),
            HashMap::new(),
            Some(1), // Very old timestamp
            None,
        );
        
        assert!(expired_secret.is_expired());
        assert!(!expired_secret.is_valid());
        
        let valid_secret = SecretId::new(
            "hash".to_string(),
            "accessor".to_string(),
            "role".to_string(),
            HashMap::new(),
            None, // No expiration
            None,
        );
        
        assert!(!valid_secret.is_expired());
        assert!(valid_secret.is_valid());
    }

    #[test]
    fn test_secret_id_usage() {
        let mut secret_id = SecretId::new(
            "hash".to_string(),
            "accessor".to_string(),
            "role".to_string(),
            HashMap::new(),
            None,
            Some(2), // Max 2 uses
        );
        
        assert_eq!(secret_id.remaining_uses(), Some(2));
        
        // First use
        assert!(secret_id.increment_usage().is_ok());
        assert_eq!(secret_id.used_count, 1);
        assert_eq!(secret_id.remaining_uses(), Some(1));
        assert!(secret_id.is_valid());
        
        // Second use
        assert!(secret_id.increment_usage().is_ok());
        assert_eq!(secret_id.used_count, 2);
        assert_eq!(secret_id.remaining_uses(), Some(0));
        assert!(!secret_id.is_valid()); // Should be invalid now
        
        // Third use should fail
        assert!(secret_id.increment_usage().is_err());
    }

    #[test]
    fn test_secret_id_deactivation() {
        let mut secret_id = SecretId::new(
            "hash".to_string(),
            "accessor".to_string(),
            "role".to_string(),
            HashMap::new(),
            None,
            None,
        );
        
        assert!(secret_id.is_valid());
        
        secret_id.deactivate();
        assert!(!secret_id.is_valid());
    }

    #[test]
    fn test_secret_id_ip_restrictions() {
        let secret_id = SecretId::new(
            "hash".to_string(),
            "accessor".to_string(),
            "role".to_string(),
            HashMap::new(),
            None,
            None,
        ).with_cidr_list(vec!["192.168.1.0/24".to_string(), "10.0.0.1".to_string()]);
        
        assert!(secret_id.is_ip_allowed("192.168.1.100"));
        assert!(secret_id.is_ip_allowed("10.0.0.1"));
        assert!(!secret_id.is_ip_allowed("172.16.0.1"));
        
        let unrestricted_secret = SecretId::new(
            "hash".to_string(),
            "accessor".to_string(),
            "role".to_string(),
            HashMap::new(),
            None,
            None,
        );
        
        assert!(unrestricted_secret.is_ip_allowed("any.ip"));
    }

    #[test]
    fn test_secret_id_validation() {
        let valid_secret = SecretId::new(
            "hash".to_string(),
            "accessor".to_string(),
            "role".to_string(),
            HashMap::new(),
            None,
            Some(5),
        );
        assert!(valid_secret.validate().is_ok());
        
        let invalid_secret = SecretId::new(
            "hash".to_string(),
            String::new(), // Empty accessor
            "role".to_string(),
            HashMap::new(),
            None,
            None,
        );
        assert!(invalid_secret.validate().is_err());
    }

    #[test]
    fn test_secret_id_response() {
        let secret_id = SecretId::new(
            "hash".to_string(),
            "accessor".to_string(),
            "role".to_string(),
            HashMap::new(),
            Some(9999999999), // Future timestamp
            Some(5),
        );
        
        let response = secret_id.to_response();
        assert_eq!(response.accessor, "accessor");
        assert_eq!(response.role_name, "role");
        assert_eq!(response.num_uses, Some(5));
        assert_eq!(response.used_count, 0);
        assert_eq!(response.remaining_uses, Some(5));
        assert!(response.time_until_expiration.is_some());
    }
}
