use anyhow::{Context, Result};
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use std::collections::HashMap;
use tracing::{debug, info};

use super::config::{LdapConfig, LdapConnectionConfig, LdapGroup, LdapUser};

/// LDAP client for handling connections and operations
pub struct LdapClient {
    config: LdapConfig,
    connection_config: LdapConnectionConfig,
}

impl LdapClient {
    /// Create a new LDAP client
    pub fn new(config: LdapConfig) -> Self {
        let connection_config = LdapConnectionConfig::from(&config);
        Self {
            config,
            connection_config,
        }
    }

    /// Create LDAP connection
    fn connect(&self) -> Result<LdapConn> {
        debug!("Connecting to LDAP server: {}", self.connection_config.url);

        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.connection_config.timeout)
            .set_starttls(self.connection_config.use_tls)
            .set_no_tls_verify(self.connection_config.insecure_tls);

        let conn = LdapConn::with_settings(settings, &self.connection_config.url)
            .context("Failed to connect to LDAP server")?;

        info!("Successfully connected to LDAP server");
        Ok(conn)
    }

    /// Authenticate user with LDAP bind
    pub fn authenticate_user(&self, username: &str, password: &str) -> Result<LdapUser> {
        let mut conn = self.connect()?;

        // Normalize username based on case sensitivity
        let normalized_username = if self.config.case_sensitive_names {
            username.to_string()
        } else {
            username.to_lowercase()
        };

        // Find user DN
        let user_dn = self.find_user_dn(&mut conn, &normalized_username)?;
        debug!("Found user DN: {}", user_dn);

        // Attempt to bind with user credentials
        conn.simple_bind(&user_dn, password)
            .context("Failed to authenticate user")?;

        info!("User {} authenticated successfully", normalized_username);

        // Get user information
        let user = self.get_user_info(&mut conn, &normalized_username, &user_dn)?;

        conn.unbind()?;
        Ok(user)
    }

    /// Find user DN by username
    fn find_user_dn(&self, conn: &mut LdapConn, username: &str) -> Result<String> {
        let filter = format!("({}={})", self.config.user_attr, username);
        debug!("Searching for user with filter: {}", filter);

        let rs = conn
            .search(&self.config.user_dn, Scope::Subtree, &filter, vec!["dn"])
            .context("Failed to search for user")?;

        if rs.0.is_empty() {
            return Err(anyhow::anyhow!("User {} not found", username));
        }

        let entry = SearchEntry::construct(rs.0[0].clone());
        Ok(entry.dn)
    }

    /// Get comprehensive user information
    fn get_user_info(
        &self,
        conn: &mut LdapConn,
        username: &str,
        user_dn: &str,
    ) -> Result<LdapUser> {
        // Search for user attributes
        let filter = format!("({}={})", self.config.user_attr, username);
        let attrs = vec!["*"];

        let rs = conn
            .search(&self.config.user_dn, Scope::Subtree, &filter, attrs)
            .context("Failed to get user attributes")?;

        if rs.0.is_empty() {
            return Err(anyhow::anyhow!(
                "User {} not found in attribute search",
                username
            ));
        }

        let entry = SearchEntry::construct(rs.0[0].clone());
        let attributes = entry.attrs;

        // Get user's group memberships
        let groups = self.get_user_groups(conn, user_dn)?;
        debug!("User {} is member of groups: {:?}", username, groups);

        // Map groups to policies
        let policies = self.map_groups_to_policies(&groups);
        debug!("User {} assigned policies: {:?}", username, policies);

        // Create metadata
        let mut metadata = HashMap::new();
        if let Some(mail) = attributes.get("mail").and_then(|v| v.first()) {
            metadata.insert("email".to_string(), mail.clone());
        }
        if let Some(cn) = attributes.get("cn").and_then(|v| v.first()) {
            metadata.insert("display_name".to_string(), cn.clone());
        }

        Ok(LdapUser {
            username: username.to_string(),
            dn: user_dn.to_string(),
            attributes,
            groups,
            policies,
            metadata,
        })
    }

    /// Get user's group memberships
    fn get_user_groups(&self, conn: &mut LdapConn, user_dn: &str) -> Result<Vec<String>> {
        let filter = if let Some(group_filter) = &self.config.group_filter {
            format!(
                "(&{}({}={}))",
                group_filter, self.config.group_attr, user_dn
            )
        } else {
            format!("({}={})", self.config.group_attr, user_dn)
        };

        debug!("Searching for groups with filter: {}", filter);

        let rs = conn
            .search(&self.config.group_dn, Scope::Subtree, &filter, vec!["cn"])
            .context("Failed to search for user groups")?;

        let mut groups = Vec::new();
        for entry in rs.0 {
            let search_entry = SearchEntry::construct(entry);
            if let Some(cn_values) = search_entry.attrs.get("cn") {
                for cn in cn_values {
                    groups.push(cn.clone());
                }
            }
        }

        Ok(groups)
    }

    /// Map LDAP groups to vault policies
    fn map_groups_to_policies(&self, groups: &[String]) -> Vec<String> {
        let mut policies = self.config.default_policies.clone();

        for group in groups {
            if let Some(group_policies) = self.config.group_policy_mappings.get(group) {
                policies.extend(group_policies.clone());
            }
        }

        // Remove duplicates while preserving order
        let mut unique_policies = Vec::new();
        for policy in policies {
            if !unique_policies.contains(&policy) {
                unique_policies.push(policy);
            }
        }

        unique_policies
    }

    /// Get information about a specific group
    pub fn get_group_info(&self, group_name: &str) -> Result<LdapGroup> {
        let mut conn = self.connect()?;

        let filter = format!("(cn={})", group_name);
        let attrs = vec!["cn", "dn", &self.config.group_attr];

        let rs = conn
            .search(&self.config.group_dn, Scope::Subtree, &filter, attrs)
            .context("Failed to search for group")?;

        if rs.0.is_empty() {
            return Err(anyhow::anyhow!("Group {} not found", group_name));
        }

        let entry = SearchEntry::construct(rs.0[0].clone());
        let members = entry
            .attrs
            .get(&self.config.group_attr)
            .cloned()
            .unwrap_or_default();

        let policies = self
            .config
            .group_policy_mappings
            .get(group_name)
            .cloned()
            .unwrap_or_default();

        conn.unbind()?;

        Ok(LdapGroup {
            name: group_name.to_string(),
            dn: entry.dn,
            members,
            policies,
        })
    }

    /// Test LDAP connection
    pub fn test_connection(&self) -> Result<()> {
        debug!("Testing LDAP connection");
        let mut conn = self.connect()?;

        // Perform a simple bind if credentials are provided
        if let (Some(bind_dn), Some(bind_password)) =
            (&self.config.bind_dn, &self.config.bind_password)
        {
            conn.simple_bind(bind_dn, bind_password)
                .context("Failed to bind with service account")?;
            info!("Service account bind successful");
        }

        conn.unbind()?;
        info!("LDAP connection test successful");
        Ok(())
    }

    /// List available groups
    pub fn list_groups(&self) -> Result<Vec<String>> {
        let mut conn = self.connect()?;

        let filter = if let Some(group_filter) = &self.config.group_filter {
            group_filter.clone()
        } else {
            "(objectClass=group)".to_string()
        };

        let rs = conn
            .search(&self.config.group_dn, Scope::Subtree, &filter, vec!["cn"])
            .context("Failed to list groups")?;

        let mut groups = Vec::new();
        for entry in rs.0 {
            let search_entry = SearchEntry::construct(entry);
            if let Some(cn_values) = search_entry.attrs.get("cn") {
                for cn in cn_values {
                    groups.push(cn.clone());
                }
            }
        }

        conn.unbind()?;
        groups.sort();
        Ok(groups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_client_creation() {
        let config = LdapConfig::default();
        let client = LdapClient::new(config);
        assert_eq!(client.connection_config.url, "ldap://localhost");
    }

    #[test]
    fn test_group_policy_mapping() {
        let mut config = LdapConfig::default();
        config.group_policy_mappings.insert(
            "developers".to_string(),
            vec!["dev-policy".to_string(), "read-policy".to_string()],
        );
        config.default_policies = vec!["default".to_string()];

        let client = LdapClient::new(config);
        let groups = vec!["developers".to_string(), "unknown-group".to_string()];
        let policies = client.map_groups_to_policies(&groups);

        assert!(policies.contains(&"default".to_string()));
        assert!(policies.contains(&"dev-policy".to_string()));
        assert!(policies.contains(&"read-policy".to_string()));
        assert_eq!(policies.len(), 3); // No duplicates
    }

    #[test]
    fn test_case_sensitivity() {
        let config = LdapConfig {
            case_sensitive_names: false,
            ..Default::default()
        };
        let client = LdapClient::new(config);

        // This test would require actual LDAP connection, so we just test the client creation
        assert!(!client.config.case_sensitive_names);
    }
}
