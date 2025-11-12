//! # LDAP Integration
//!
//! Directory service integration for LDAP and Active Directory operations.
//! Provides abstracted LDAP operations for authentication, user management, and directory operations.

use ldap3::{LdapConnAsync, Mod, SearchEntry};
use secreton_errors::{Result, SecretonError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// LDAP configuration for connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub tls_enabled: bool,
    pub ca_cert: Option<String>,
}

/// LDAP connection manager with automatic cleanup
pub struct LdapConnection {
    ldap: LdapConnAsync,
}

impl LdapConnection {
    /// Create new LDAP connection with configuration
    pub async fn new(config: &LdapConfig) -> Result<Self> {
        let (conn, mut ldap) = LdapConnAsync::new(&config.url).await.map_err(|e| {
            SecretonError::BackendOperationFailed(format!("LDAP connection failed: {}", e))
        })?;

        // Start TLS if enabled
        if config.tls_enabled {
            ldap.start_tls().await.map_err(|e| {
                SecretonError::BackendOperationFailed(format!("LDAP TLS failed: {}", e))
            })?;
        }

        // Bind with credentials
        ldap.simple_bind(&config.bind_dn, &config.bind_password)
            .await
            .map_err(|e| SecretonError::AuthError(format!("LDAP bind failed: {}", e)))?;

        Ok(Self { ldap })
    }

    /// Get reference to LDAP connection for operations
    pub fn conn(&mut self) -> &mut LdapConnAsync {
        &mut self.ldap
    }

    /// Execute search operation
    pub async fn search(
        &mut self,
        base_dn: &str,
        scope: ldap3::Scope,
        filter: &str,
        attrs: Vec<&str>,
    ) -> Result<Vec<SearchEntry>> {
        let (rs, _res) = self
            .ldap
            .search(base_dn, scope, filter, attrs)
            .await
            .map_err(|e| {
                SecretonError::BackendOperationFailed(format!("LDAP search failed: {}", e))
            })?
            .success()
            .map_err(|e| {
                SecretonError::BackendOperationFailed(format!(
                    "LDAP search verification failed: {}",
                    e
                ))
            })?;

        Ok(rs
            .into_iter()
            .map(SearchEntry::construct)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                SecretonError::BackendOperationFailed(format!("LDAP entry parsing failed: {}", e))
            })?)
    }

    /// Execute add operation
    pub async fn add(
        &mut self,
        dn: &str,
        attrs: Vec<(&str, HashMap<String, String>)>,
    ) -> Result<()> {
        let ldap_attrs: Vec<_> = attrs
            .into_iter()
            .map(|(name, values)| {
                (
                    name,
                    std::collections::HashSet::from_iter(values.into_values()),
                )
            })
            .collect();

        self.ldap.add(dn, ldap_attrs).await.map_err(|e| {
            SecretonError::BackendOperationFailed(format!("LDAP add failed for {}: {}", dn, e))
        })?;

        Ok(())
    }

    /// Execute modify operation
    pub async fn modify(&mut self, dn: &str, modifications: Vec<Mod<String>>) -> Result<()> {
        self.ldap.modify(dn, modifications).await.map_err(|e| {
            SecretonError::BackendOperationFailed(format!("LDAP modify failed for {}: {}", dn, e))
        })?;

        Ok(())
    }

    /// Execute delete operation
    pub async fn delete(&mut self, dn: &str) -> Result<()> {
        self.ldap.delete(dn).await.map_err(|e| {
            SecretonError::BackendOperationFailed(format!("LDAP delete failed for {}: {}", dn, e))
        })?;

        Ok(())
    }

    /// Unbind and close connection
    pub async fn close(mut self) -> Result<()> {
        self.ldap.unbind().await.map_err(|e| {
            SecretonError::BackendOperationFailed(format!("LDAP unbind failed: {}", e))
        })?;
        Ok(())
    }
}

/// Password encoding for Active Directory
pub fn encode_ad_password(password: &str) -> String {
    // Active Directory requires UTF-16LE encoding with quotes
    format!("\"{}\"", password)
}

/// Password encoding for OpenLDAP
pub fn encode_ldap_password(password: &str) -> String {
    // OpenLDAP typically uses plain text or SSHA
    password.to_string()
}

/// Common LDAP operations
pub struct LdapOperations;

impl LdapOperations {
    /// Create user with common attributes
    pub async fn create_user(
        conn: &mut LdapConnection,
        dn: &str,
        username: &str,
        password: &str,
        schema: LdapSchema,
    ) -> Result<()> {
        let attrs = match schema {
            LdapSchema::ActiveDirectory => vec![
                (
                    "objectClass",
                    vec![
                        "top".to_string(),
                        "person".to_string(),
                        "organizationalPerson".to_string(),
                        "user".to_string(),
                    ]
                    .into_iter()
                    .collect(),
                ),
                ("cn", vec![username.to_string()].into_iter().collect()),
                ("sn", vec![username.to_string()].into_iter().collect()),
                (
                    "userPrincipalName",
                    vec![format!("{}@domain.com", username)]
                        .into_iter()
                        .collect(),
                ),
                (
                    "sAMAccountName",
                    vec![username.to_string()].into_iter().collect(),
                ),
                (
                    "userAccountControl",
                    vec!["512".to_string()].into_iter().collect(),
                ), // Normal account
            ],
            LdapSchema::OpenLDAP => vec![
                (
                    "objectClass",
                    vec![
                        "top".to_string(),
                        "person".to_string(),
                        "organizationalPerson".to_string(),
                        "inetOrgPerson".to_string(),
                    ]
                    .into_iter()
                    .collect(),
                ),
                ("cn", vec![username.to_string()].into_iter().collect()),
                ("sn", vec![username.to_string()].into_iter().collect()),
                ("uid", vec![username.to_string()].into_iter().collect()),
            ],
        };

        conn.add(dn, attrs).await?;

        // Set password separately for AD
        if matches!(schema, LdapSchema::ActiveDirectory) {
            let encoded_password = encode_ad_password(password);
            let mod_op = Mod::Replace(
                "unicodePwd",
                std::collections::HashSet::from([encoded_password.into_bytes()]),
            );
            conn.modify(dn, vec![mod_op]).await?;
        }

        Ok(())
    }

    /// Change user password
    pub async fn change_password(
        conn: &mut LdapConnection,
        dn: &str,
        new_password: &str,
        schema: LdapSchema,
    ) -> Result<()> {
        let encoded_password = match schema {
            LdapSchema::ActiveDirectory => encode_ad_password(new_password),
            LdapSchema::OpenLDAP => encode_ldap_password(new_password),
        };

        let mod_op = match schema {
            LdapSchema::ActiveDirectory => Mod::Replace(
                "unicodePwd",
                std::collections::HashSet::from([encoded_password.into_bytes()]),
            ),
            LdapSchema::OpenLDAP => Mod::Replace(
                "userPassword",
                std::collections::HashSet::from([encoded_password]),
            ),
        };

        conn.modify(dn, vec![mod_op]).await
    }

    /// Delete user
    pub async fn delete_user(conn: &mut LdapConnection, dn: &str) -> Result<()> {
        conn.delete(dn).await
    }
}

/// LDAP schema types
#[derive(Debug, Clone, Copy)]
pub enum LdapSchema {
    ActiveDirectory,
    OpenLDAP,
}
