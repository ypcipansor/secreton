//! LDAP authentication method

use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use chrono::Utc;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use secreton_errors::SecretonError;
use std::collections::HashMap;
use uuid::Uuid;

/// LDAP authentication method
pub struct LdapAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    ldap_config: Option<LdapConfig>,
}

impl LdapAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            ldap_config: None,
        }
    }

    /// Set LDAP configuration
    pub fn set_ldap_config(&mut self, config: LdapConfig) {
        self.ldap_config = Some(config);
    }

    /// Bind to LDAP server
    async fn bind_ldap(&self, username: &str, password: &str) -> AuthMethodResult<ldap3::Ldap> {
        let config = self
            .ldap_config
            .as_ref()
            .ok_or_else(|| SecretonError::Configuration {
                message: "LDAP config not set".to_string(),
            })?;

        let (conn, mut ldap) =
            LdapConnAsync::new(&config.url)
                .await
                .map_err(|e| SecretonError::Network {
                    message: format!("LDAP connection failed: {e}"),
                })?;

        ldap3::drive!(conn);

        // Try to bind with user credentials
        let bind_dn = if config.user_dn_template.contains("{username}") {
            config.user_dn_template.replace("{username}", username)
        } else {
            format!(
                "{}={},{}",
                config.user_attr, username, config.user_dn_template
            )
        };

        ldap.simple_bind(&bind_dn, password)
            .await
            .map_err(|e| SecretonError::Authentication {
                message: format!("LDAP bind failed: {e}"),
            })?
            .success()
            .map_err(|e| SecretonError::Authentication {
                message: format!("LDAP bind unsuccessful: {e}"),
            })?;

        Ok(ldap)
    }

    /// Get user information from LDAP
    async fn get_user_info(
        &self,
        ldap: &mut ldap3::Ldap,
        username: &str,
    ) -> AuthMethodResult<UserInfo> {
        let config = self
            .ldap_config
            .as_ref()
            .ok_or_else(|| SecretonError::Configuration {
                message: "LDAP config not set".to_string(),
            })?;

        let filter = format!("({}={})", config.user_attr, username);
        let search_result = ldap
            .search(
                &config.user_dn_template,
                Scope::Subtree,
                &filter,
                vec![
                    "dn",
                    "cn",
                    "memberOf",
                    &config.user_attr,
                    "mail",
                    "displayName",
                ],
            )
            .await
            .map_err(|e| SecretonError::Network {
                message: format!("LDAP search failed: {e}"),
            })?
            .success()
            .map_err(|e| SecretonError::Network {
                message: format!("LDAP search error: {e}"),
            })?;

        if let Some(entry) = search_result.0.into_iter().next() {
            let search_entry = SearchEntry::construct(entry);
            let roles = search_entry
                .attrs
                .get("memberOf")
                .map(|members| members.iter().map(|dn| extract_group_name(dn)).collect())
                .unwrap_or_default();

            let mut metadata = HashMap::new();
            metadata.insert("dn".to_string(), search_entry.dn.clone());
            metadata.insert("filter".to_string(), filter);

            Ok(UserInfo {
                id: Some(Uuid::new_v4().to_string()),
                username: username.to_string(),
                email: search_entry
                    .attrs
                    .get("mail")
                    .and_then(|v| v.first())
                    .cloned(),
                display_name: search_entry
                    .attrs
                    .get("displayName")
                    .and_then(|v| v.first())
                    .cloned(),
                roles,
                metadata,
                last_login: Some(Utc::now()),
            })
        } else {
            Err(SecretonError::UserNotFound {
                username: username.to_string(),
            })
        }
    }
}

#[async_trait]
impl AuthMethodImpl for LdapAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::Ldap
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.clone());

        // Parse LDAP configuration from config
        if let Some(ldap_url) = config.config.get("url").and_then(|v| v.as_str()) {
            let ldap_config = LdapConfig {
                url: ldap_url.to_string(),
                user_dn_template: config
                    .config
                    .get("user_dn_template")
                    .or_else(|| config.config.get("user_dn"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("ou=users,dc=example,dc=com")
                    .to_string(),
                user_attr: config
                    .config
                    .get("user_attr")
                    .and_then(|v| v.as_str())
                    .unwrap_or("cn")
                    .to_string(),
                group_attr: config
                    .config
                    .get("group_attr")
                    .and_then(|v| v.as_str())
                    .unwrap_or("memberOf")
                    .to_string(),
                bind_dn: config
                    .config
                    .get("bind_dn")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                bind_password: config
                    .config
                    .get("bind_password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                start_tls: config
                    .config
                    .get("start_tls")
                    .or_else(|| config.config.get("starttls"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            };
            self.ldap_config = Some(ldap_config);
        }

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        if !self.is_enabled() {
            return Err(SecretonError::AuthMethodDisabled);
        }

        match credentials {
            AuthCredentials::UserPass { username, password } => {
                let mut ldap = self.bind_ldap(username, password).await?;
                let user_info = self.get_user_info(&mut ldap, username).await?;

                Ok(AuthResult {
                    success: true,
                    user_info: Some(user_info),
                    token: None,
                    mfa_required: false,
                    policies: vec![], // Policies would be determined by groups
                    metadata: HashMap::new(),
                })
            }
            _ => Err(SecretonError::InvalidCredentials),
        }
    }

    async fn validate_token(&self, _token: &str) -> AuthMethodResult<UserInfo> {
        Err(SecretonError::AuthMethodNotSupported)
    }

    async fn revoke_token(&self, _token: &str) -> AuthMethodResult<()> {
        Err(SecretonError::AuthMethodNotSupported)
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}

/// LDAP configuration
#[derive(Clone, Debug)]
pub struct LdapConfig {
    pub url: String,
    pub user_dn_template: String,
    pub user_attr: String,
    pub group_attr: String,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub start_tls: bool,
}

/// Extract group name from DN
fn extract_group_name(dn: &str) -> String {
    // Simple extraction - could be made more sophisticated
    if let Some(cn_start) = dn.find("CN=") {
        let cn_part = &dn[cn_start + 3..];
        if let Some(comma_pos) = cn_part.find(',') {
            cn_part[..comma_pos].to_string()
        } else {
            cn_part.to_string()
        }
    } else {
        dn.to_string()
    }
}
