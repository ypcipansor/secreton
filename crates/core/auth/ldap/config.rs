use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// LDAP authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL (ldap:// or ldaps://)
    pub url: String,

    /// LDAP server port (389 for ldap, 636 for ldaps)
    pub port: u16,

    /// Use TLS/SSL for connection
    pub use_tls: bool,

    /// Skip TLS certificate verification (for development only)
    pub insecure_tls: bool,

    /// Base DN for user searches
    pub user_dn: String,

    /// User attribute for username (typically 'uid' or 'sAMAccountName')
    pub user_attr: String,

    /// Base DN for group searches
    pub group_dn: String,

    /// Group attribute for membership (typically 'member' or 'memberUid')
    pub group_attr: String,

    /// Group filter for limiting group searches
    pub group_filter: Option<String>,

    /// Bind DN for service account (for group searches)
    pub bind_dn: Option<String>,

    /// Bind password for service account
    pub bind_password: Option<String>,

    /// Connection timeout in seconds
    pub timeout: u64,

    /// Maximum number of connections in pool
    pub max_connections: u32,

    /// Group to policy mappings
    pub group_policy_mappings: HashMap<String, Vec<String>>,

    /// Default policies for authenticated users
    pub default_policies: Vec<String>,

    /// Case sensitivity for usernames
    pub case_sensitive_names: bool,

    /// Request timeout in seconds
    pub request_timeout: u64,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            url: "ldap://localhost".to_string(),
            port: 389,
            use_tls: true,
            insecure_tls: false,
            user_dn: "ou=people,dc=example,dc=com".to_string(),
            user_attr: "uid".to_string(),
            group_dn: "ou=groups,dc=example,dc=com".to_string(),
            group_attr: "member".to_string(),
            group_filter: None,
            bind_dn: None,
            bind_password: None,
            timeout: 30,
            max_connections: 10,
            group_policy_mappings: HashMap::new(),
            default_policies: vec!["default".to_string()],
            case_sensitive_names: false,
            request_timeout: 10,
        }
    }
}

/// LDAP user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUser {
    /// Username
    pub username: String,

    /// User DN
    pub dn: String,

    /// User attributes
    pub attributes: HashMap<String, Vec<String>>,

    /// Group memberships
    pub groups: Vec<String>,

    /// Mapped policies from groups
    pub policies: Vec<String>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// LDAP group information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapGroup {
    /// Group name
    pub name: String,

    /// Group DN
    pub dn: String,

    /// Group members
    pub members: Vec<String>,

    /// Mapped policies
    pub policies: Vec<String>,
}

/// LDAP authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapAuthRequest {
    /// Username
    pub username: String,

    /// Password
    pub password: String,

    /// Optional additional metadata
    pub metadata: Option<HashMap<String, String>>,
}

/// LDAP authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapAuthResponse {
    /// Authentication success
    pub success: bool,

    /// User information
    pub user: Option<LdapUser>,

    /// Error message if authentication failed
    pub error: Option<String>,

    /// Token TTL in seconds
    pub ttl: Option<u64>,

    /// Renewable token flag
    pub renewable: bool,
}

/// LDAP connection configuration
#[derive(Debug, Clone)]
pub struct LdapConnectionConfig {
    /// Full LDAP URL
    pub url: String,

    /// Connection timeout
    pub timeout: std::time::Duration,

    /// Use TLS
    pub use_tls: bool,

    /// Skip certificate verification
    pub insecure_tls: bool,
}

impl From<&LdapConfig> for LdapConnectionConfig {
    fn from(config: &LdapConfig) -> Self {
        let protocol = if config.use_tls { "ldaps" } else { "ldap" };
        let url = if config.url.starts_with("ldap://") || config.url.starts_with("ldaps://") {
            config.url.clone()
        } else {
            format!("{}://{}:{}", protocol, config.url, config.port)
        };

        Self {
            url,
            timeout: std::time::Duration::from_secs(config.timeout),
            use_tls: config.use_tls,
            insecure_tls: config.insecure_tls,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_config_default() {
        let config = LdapConfig::default();
        assert_eq!(config.url, "ldap://localhost");
        assert_eq!(config.port, 389);
        assert!(config.use_tls);
        assert!(!config.insecure_tls);
        assert_eq!(config.user_attr, "uid");
        assert_eq!(config.timeout, 30);
    }

    #[test]
    fn test_ldap_connection_config_from_ldap_config() {
        let ldap_config = LdapConfig {
            url: "ldap.example.com".to_string(),
            port: 636,
            use_tls: true,
            timeout: 60,
            ..Default::default()
        };

        let conn_config = LdapConnectionConfig::from(&ldap_config);
        assert_eq!(conn_config.url, "ldaps://ldap.example.com:636");
        assert!(conn_config.use_tls);
        assert_eq!(conn_config.timeout.as_secs(), 60);
    }

    #[test]
    fn test_ldap_auth_request() {
        let auth_req = LdapAuthRequest {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            metadata: None,
        };

        assert_eq!(auth_req.username, "testuser");
        assert_eq!(auth_req.password, "testpass");
        assert!(auth_req.metadata.is_none());
    }

    #[test]
    fn test_ldap_user_creation() {
        let mut attributes = HashMap::new();
        attributes.insert("mail".to_string(), vec!["user@example.com".to_string()]);

        let user = LdapUser {
            username: "testuser".to_string(),
            dn: "uid=testuser,ou=people,dc=example,dc=com".to_string(),
            attributes,
            groups: vec!["developers".to_string(), "users".to_string()],
            policies: vec!["dev-policy".to_string(), "default".to_string()],
            metadata: HashMap::new(),
        };

        assert_eq!(user.username, "testuser");
        assert_eq!(user.groups.len(), 2);
        assert_eq!(user.policies.len(), 2);
    }
}
