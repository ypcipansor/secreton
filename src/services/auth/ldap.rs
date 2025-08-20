use ldap3::{LdapConnAsync, Scope};
use crate::utils::config::Config;

pub async fn ldap_authenticate(config: &Config, username: &str, password: &str) -> Result<bool, String> {
    let url = config.ldap_url.as_ref().ok_or("ldap_url not set")?;
    let base_dn = config.ldap_base_dn.as_ref().ok_or("ldap_base_dn not set")?;
    let (conn, mut ldap) = LdapConnAsync::new(url).await.map_err(|e| e.to_string())?;
    let bind_dn = format!("uid={},{}", username, base_dn);
    let res = ldap.simple_bind(&bind_dn, password).await.map_err(|e| e.to_string())?.success();
    Ok(res.is_ok())
} 