use crate::models::auth::{AuthRequest, AuthResponse, UserInfo};
use chrono::Utc;
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_dn: String,
    pub user_attr: String,
    pub group_attr: String,
    pub group_dn: Option<String>,
    pub group_filter: Option<String>,
    pub certificate: Option<String>,
    pub insecure_tls: bool,
    pub start_tls: bool,
    pub connection_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUser {
    pub dn: String,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
    pub attributes: HashMap<String, Vec<String>>,
}

pub struct LdapAuth {
    config: LdapConfig,
}

impl LdapAuth {
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }

    pub async fn authenticate(
        &self,
        auth_request: &AuthRequest,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        match auth_request {
            AuthRequest::UserPass { username, password } => {
                self.authenticate_credentials(username, password).await
            }
            AuthRequest::Ldap { username, password } => {
                self.authenticate_credentials(username, password).await
            }
            _ => Err("LDAP authentication only supports username/password credentials".into()),
        }
    }

    async fn authenticate_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Establish LDAP connection
        let mut ldap = self.create_ldap_connection().await?;

        // Bind with service account to search for user
        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)?
            .success()?;

        // Search for user
        let user_dn = self.find_user_dn(&mut ldap, username).await?;

        // Bind as user to verify credentials
        let result = ldap.simple_bind(&user_dn, password)?;

        if result.rc != 0 {
            return Ok(AuthResponse {
                authenticated: false,
                user_info: UserInfo {
                    username: username.to_string(),
                    email: None,
                    groups: vec![],
                    metadata: HashMap::new(),
                },
                policies: vec![],
                lease_duration: 0,
                renewable: false,
                token: "".to_string(),
                accessor: "".to_string(),
                metadata: HashMap::new(),
            });
        }

        // Re-bind as service account to get user details
        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)?
            .success()?;

        // Get user details and groups
        let user_details = self.get_user_details(&mut ldap, &user_dn).await?;
        let groups = self.get_user_groups(&mut ldap, &user_dn, username).await?;

        // Unbind
        ldap.unbind()?;

        let token = self.generate_token(&user_details.username);

        Ok(AuthResponse {
            authenticated: true,
            user_info: UserInfo {
                username: user_details.username.clone(),
                email: user_details.email,
                groups,
                metadata: user_details
                    .attributes
                    .into_iter()
                    .map(|(k, v)| (k, v.join(", ")))
                    .collect(),
            },
            policies: vec!["default".to_string()],
            lease_duration: 3600, // 1 hour default
            renewable: true,
            token,
            accessor: format!("ldap-{}", user_details.username),
            metadata: HashMap::new(),
        })
    }

    async fn create_ldap_connection(
        &self,
    ) -> Result<LdapConn, Box<dyn std::error::Error + Send + Sync>> {
        let mut settings = LdapConnSettings::new();

        if self.config.insecure_tls {
            settings = settings.set_no_tls_verify(true);
        }

        if let Some(_cert) = &self.config.certificate {
            // TODO: Fix LDAP cert configuration - API may have changed
            // settings = settings.set_ca_cert_file(cert);
        }

        let ldap = LdapConn::with_settings(settings, &self.config.url)?;

        if self.config.start_tls {
            // TODO: Fix start_tls method call - API may have changed
            // ldap.start_tls().await?;
        }

        Ok(ldap)
    }

    async fn find_user_dn(
        &self,
        ldap: &mut LdapConn,
        username: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let filter = format!(
            "(&({}={})(objectClass=user))",
            self.config.user_attr, username
        );
        let search_result = ldap.search(
            &self.config.user_dn,
            Scope::Subtree,
            &filter,
            vec!["dn", "cn", "name", "memberOf"],
        )?;

        let entries = search_result.0;
        if entries.is_empty() {
            return Err(format!("User {} not found", username).into());
        }

        if entries.len() > 1 {
            return Err(format!("Multiple users found for {}", username).into());
        }

        let entry = SearchEntry::construct(entries.into_iter().next().unwrap());
        Ok(entry.dn)
    }

    async fn get_user_details(
        &self,
        ldap: &mut LdapConn,
        user_dn: &str,
    ) -> Result<LdapUser, Box<dyn std::error::Error + Send + Sync>> {
        let attrs = vec![
            "dn",
            "cn",
            "sn",
            "givenName",
            "mail",
            "displayName",
            "memberOf",
            "sAMAccountName",
            "userPrincipalName",
            "uid",
        ];

        let search_result = ldap.search(user_dn, Scope::Base, "(objectClass=*)", attrs)?;

        let entries = search_result.0;
        if entries.is_empty() {
            return Err("User details not found".into());
        }

        let entry = SearchEntry::construct(entries.into_iter().next().unwrap());

        let username = entry
            .attrs
            .get(&self.config.user_attr)
            .and_then(|v| v.first())
            .unwrap_or(&"unknown".to_string())
            .clone();

        let email = entry.attrs.get("mail").and_then(|v| v.first()).cloned();

        let display_name = entry
            .attrs
            .get("displayName")
            .or_else(|| entry.attrs.get("cn"))
            .and_then(|v| v.first())
            .cloned();

        let mut attributes = HashMap::new();
        for (key, values) in &entry.attrs {
            attributes.insert(key.clone(), values.clone());
        }

        Ok(LdapUser {
            dn: entry.dn,
            username,
            email,
            display_name,
            groups: vec![], // Will be populated separately
            attributes,
        })
    }

    async fn get_user_groups(
        &self,
        ldap: &mut LdapConn,
        user_dn: &str,
        username: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let mut groups = Vec::new();

        // Method 1: Get groups from user's memberOf attribute
        if let Ok(user_details) = self.get_user_details(ldap, user_dn).await {
            if let Some(member_of) = user_details.attributes.get("memberOf") {
                for group_dn in member_of {
                    if let Some(group_name) = self.extract_group_name(group_dn) {
                        groups.push(group_name);
                    }
                }
            }
        }

        // Method 2: Search for groups containing the user
        if let Some(group_dn) = &self.config.group_dn {
            let filter = self
                .config
                .group_filter
                .as_ref()
                .map(|f| f.replace("{username}", username))
                .unwrap_or_else(|| format!("(member={})", user_dn));

            let search_result =
                ldap.search(group_dn, Scope::Subtree, &filter, vec!["dn", "cn", "name"])?;

            for entry in search_result.0 {
                let entry = SearchEntry::construct(entry);
                let group_name = entry
                    .attrs
                    .get("cn")
                    .or_else(|| entry.attrs.get("name"))
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| self.extract_group_name(&entry.dn).unwrap_or_default());

                if !group_name.is_empty() && !groups.contains(&group_name) {
                    groups.push(group_name);
                }
            }
        }

        Ok(groups)
    }

    fn extract_group_name(&self, group_dn: &str) -> Option<String> {
        // Extract CN from DN like "CN=Group Name,OU=Groups,DC=example,DC=com"
        if let Some(cn_start) = group_dn.to_lowercase().find("cn=") {
            let cn_part = &group_dn[cn_start + 3..];
            if let Some(comma_pos) = cn_part.find(',') {
                Some(cn_part[..comma_pos].to_string())
            } else {
                Some(cn_part.to_string())
            }
        } else {
            None
        }
    }

    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // For LDAP, we don't maintain session tokens
        // Token validation would need to be implemented separately
        // For now, assume tokens are valid for their duration
        Ok(!token.is_empty())
    }

    pub async fn list_users(
        &self,
    ) -> Result<Vec<LdapUser>, Box<dyn std::error::Error + Send + Sync>> {
        let mut ldap = self.create_ldap_connection().await?;

        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)?
            .success()?;

        let filter = "(objectClass=user)";
        let attrs = vec!["dn", "cn", "mail", "displayName", &self.config.user_attr];

        let search_result = ldap.search(&self.config.user_dn, Scope::Subtree, filter, attrs)?;

        let mut users = Vec::new();
        for entry in search_result.0 {
            let entry = SearchEntry::construct(entry);

            let username = entry
                .attrs
                .get(&self.config.user_attr)
                .and_then(|v| v.first())
                .unwrap_or(&"unknown".to_string())
                .clone();

            let email = entry.attrs.get("mail").and_then(|v| v.first()).cloned();

            let display_name = entry
                .attrs
                .get("displayName")
                .or_else(|| entry.attrs.get("cn"))
                .and_then(|v| v.first())
                .cloned();

            let mut attributes = HashMap::new();
            for (key, values) in &entry.attrs {
                attributes.insert(key.clone(), values.clone());
            }

            users.push(LdapUser {
                dn: entry.dn,
                username,
                email,
                display_name,
                groups: vec![], // Groups would need separate query
                attributes,
            });
        }

        ldap.unbind()?;
        Ok(users)
    }

    pub async fn list_groups(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(group_dn) = &self.config.group_dn {
            let mut ldap = self.create_ldap_connection().await?;

            ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)?
                .success()?;

            let filter = "(objectClass=group)";
            let attrs = vec!["dn", "cn", "name"];

            let search_result = ldap.search(group_dn, Scope::Subtree, filter, attrs)?;

            let mut groups = Vec::new();
            for entry in search_result.0 {
                let entry = SearchEntry::construct(entry);
                let group_name = entry
                    .attrs
                    .get("cn")
                    .or_else(|| entry.attrs.get("name"))
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| self.extract_group_name(&entry.dn).unwrap_or_default());

                if !group_name.is_empty() {
                    groups.push(group_name);
                }
            }

            ldap.unbind()?;
            Ok(groups)
        } else {
            Ok(vec![])
        }
    }

    fn generate_token(&self, username: &str) -> String {
        // In a real implementation, this would generate a proper JWT or session token
        format!("ldap-token-{}-{}", username, Utc::now().timestamp())
    }
}

/// Simple LDAP authentication function for backward compatibility
pub async fn ldap_authenticate(
    config: &crate::utils::config::Config,
    username: &str,
    password: &str,
) -> Result<bool, String> {
    let url = config.ldap_url.as_ref().ok_or("ldap_url not set")?;
    let base_dn = config.ldap_base_dn.as_ref().ok_or("ldap_base_dn not set")?;
    let (_conn, mut ldap) = ldap3::LdapConnAsync::new(url)
        .await
        .map_err(|e| e.to_string())?;
    let bind_dn = format!("uid={},{}", username, base_dn);
    let res = ldap
        .simple_bind(&bind_dn, password)
        .await
        .map_err(|e| e.to_string())?
        .success();
    Ok(res.is_ok())
}
