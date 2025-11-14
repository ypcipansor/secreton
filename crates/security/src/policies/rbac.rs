use crate::policies::policy::Policy;
// use crate::services::policy::PolicySet; // COMMENTED: policy module disabled

/* COMMENTED: PolicySet dependency from disabled policy module
pub fn check_policy_with_policyset(
    user: &str,
    path: &str,
    action: &str,
    policies_json: &str,
    context: Option<&Value>,
) -> bool {
    if let Ok(policy_set) = serde_json::from_str::<PolicySet>(policies_json) {
        policy_set.evaluate(user, path, action, context)
    } else {
        false
    }
}
*/

// Update check_policy agar bisa fallback ke policy as code jika ada
pub fn check_policy(
    roles: &[String],
    policies: &[Policy],
    path: &str,
    action: &str,
    _policyset_json: Option<&str>,
) -> bool {
    // Cek policy RBAC tradisional
    for policy in policies {
        if roles.contains(&policy.role)
            && policy.action == action
            && glob::Pattern::new(&policy.path)
                .map(|p| p.matches(path))
                .unwrap_or(false)
        {
            if policy.effect == "deny" {
                return false;
            }
            if policy.effect == "allow" {
                return true;
            }
        }
    }
    // Fallback ke policy as code jika ada
    // COMMENTED: check_policy_with_policyset function disabled due to missing PolicySet dependency
    // if let Some(json) = policyset_json {
    //     return check_policy_with_policyset("", path, action, json, None);
    // }
    false
}

/// Resolve roles for a user, including via entity_alias (OIDC/LDAP/AppRole)
pub fn resolve_user_roles(
    user_id: &str,
    entity_alias: Option<&str>,
    policies: &[Policy],
) -> Vec<String> {
    let mut roles = Vec::new();
    for policy in policies {
        if let Some(alias) = &policy.entity_alias
            && let Some(user_alias) = entity_alias
            && alias == user_alias
        {
            roles.push(policy.role.clone());
        }
        // fallback: user_id langsung sebagai role
        if policy.role == user_id {
            roles.push(policy.role.clone());
        }
    }
    roles
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::policy::Policy;

    #[test]
    fn test_policy_globbing() {
        let policies = vec![Policy {
            id: 1,
            role: "admin".to_string(),
            path: "secret/data/*".to_string(),
            action: "read".to_string(),
            namespace: "default".to_string(),
            effect: "allow".to_string(),
            entity_alias: None,
        }];
        let roles = vec!["admin".to_string()];
        assert!(check_policy(
            &roles,
            &policies,
            "secret/data/foo",
            "read",
            None
        ));
        assert!(!check_policy(&roles, &policies, "sys/config", "read", None));
    }

    #[test]
    fn test_entity_alias() {
        let policies = vec![Policy {
            id: 2,
            role: "oidc_user".to_string(),
            path: "secret/data/*".to_string(),
            action: "read".to_string(),
            namespace: "default".to_string(),
            effect: "allow".to_string(),
            entity_alias: Some("oidc:1234".to_string()),
        }];
        let roles = resolve_user_roles("userx", Some("oidc:1234"), &policies);
        assert!(roles.contains(&"oidc_user".to_string()));
        assert!(check_policy(
            &roles,
            &policies,
            "secret/data/bar",
            "read",
            None
        ));
    }
}
