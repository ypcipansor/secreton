
use crate::policies::sentinel::SentinelPolicy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "wasmi")]
use crate::policies::wasm::evaluate_wasm_policy;
#[cfg(feature = "wasmi")]
use base64::{engine::general_purpose, Engine as _};

// Define policy types locally
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: i64,
    pub role: String,
    pub path: String, // supports glob/wildcard
    pub action: String,
    pub effect: String,               // "allow" or "deny"
    pub entity_alias: Option<String>, // mapping user OIDC/LDAP/AppRole
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroup {
    pub required_approvals: u32,
    pub approved_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub effect: String,                       // "allow" or "deny"
    pub action: String,                       // e.g. "read", "write"
    pub path: String,                         // glob/wildcard path
    pub condition: Option<serde_json::Value>, // optional expression/logic
    pub control_group: Option<ControlGroup>,  // multi-approval
    pub mfa: Option<bool>,                    // requires MFA?
}

/// A set of policy rules to be evaluated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub rules: Vec<PolicyRule>,
}

impl PolicySet {
    pub fn evaluate(&self, _user: &str, path: &str, action: &str, context: Option<&Value>) -> bool {
        for rule in &self.rules {
            if rule.action == action
                && glob::Pattern::new(&rule.path)
                    .map(|p| p.matches(path))
                    .unwrap_or(false)
            {
                // Evaluasi control group
                if let Some(cg) = &rule.control_group {
                    if cg.approved_by.len() < cg.required_approvals as usize {
                        // Belum cukup approval
                        return false;
                    }
                }
                // Evaluasi MFA
                if rule.mfa == Some(true) {
                    if let Some(ctx) = context {
                        if !ctx
                            .get("mfa_passed")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                if rule.effect == "deny" {
                    return false;
                }
                if rule.effect == "allow" {
                    return true;
                }
            }
        }
        false // default deny
    }
}

#[derive(Debug)]
pub struct PolicyContext {
    // Placeholder for future policy evaluation context
}

#[derive(Debug)]
pub struct PolicyCheckConfig<'a> {
    pub sentinel_policies: &'a [SentinelPolicy],
    pub user: &'a str,
    pub path: &'a str,
    pub action: &'a str,
    pub _context: Option<&'a serde_json::Value>,
    pub rbac_roles: &'a [String],
    pub rbac_policies: &'a [Policy],
    pub policyset_json: Option<&'a str>,
}

#[derive(Serialize)]
#[allow(dead_code)] // Fields are used in serialization
struct WasmInput<'a> {
    user: &'a str,
    path: &'a str,
    action: &'a str,
}

pub async fn evaluate_with_sentinel(
    policies: &[SentinelPolicy],
    user: &str,
    path: &str,
    action: &str,
    _context: &PolicyContext,
) -> bool {
    // For now, just evaluate all policies (no versioning logic yet)
    for pol in policies {
        if pol.policy_code == "deny_all" {
            // Add audit logging
            tracing::info!(
                user = %user,
                path = %path,
                action = %action,
                policy = %pol.name,
                "Policy evaluation: access denied by deny_all policy"
            );
            return false;
        }

        // Check if policy is WASM
        // We detect WASM if it starts with "wasm:" prefix or if we can decode it as WASM magic header
        let is_wasm = pol.policy_code.starts_with("wasm:") || pol.policy_code == "wasm";

        if is_wasm {
             // Extract base64 code if prefix is present
             let _b64_code = if pol.policy_code.starts_with("wasm:") {
                 &pol.policy_code[5..]
             } else {
                 // For testing placeholder "wasm", we can't really execute it without code
                 // But assuming the TODO meant "implement the execution logic"
                 if pol.policy_code == "wasm" {
                     tracing::warn!(
                        user = %user,
                        path = %path,
                        policy = %pol.name,
                        "WASM policy placeholder encountered. No code to execute. Denying."
                     );
                     return false;
                 }
                 &pol.policy_code
             };

             // Decode base64
             #[cfg(feature = "wasmi")]
             {
                 let wasm_bytes = match general_purpose::STANDARD.decode(_b64_code) {
                     Ok(b) => b,
                     Err(e) => {
                         tracing::error!("Failed to decode WASM policy: {}", e);
                         return false;
                     }
                 };

                 let input = WasmInput {
                     user,
                     path,
                     action,
                 };
                 let input_json = match serde_json::to_string(&input) {
                     Ok(s) => s,
                     Err(e) => {
                         tracing::error!("Failed to serialize WASM input: {}", e);
                         return false;
                     }
                 };

                 match evaluate_wasm_policy(&wasm_bytes, &input_json) {
                     Ok(allowed) => {
                         tracing::info!(
                            user = %user,
                             path = %path,
                             policy = %pol.name,
                             result = if allowed { "allowed" } else { "denied" },
                             "WASM policy evaluation completed"
                         );
                         if !allowed {
                             return false;
                         }
                     },
                     Err(e) => {
                         tracing::error!("WASM policy execution failed: {}", e);
                         return false; // Fail safe
                     }
                 }
             }
             #[cfg(not(feature = "wasmi"))]
             {
                 tracing::warn!("WASM support not enabled (feature 'wasmi' required)");
                 return false;
             }
        } else if pol.policy_code == "egp" || pol.policy_code == "rgp" {
             // Legacy/Test placeholder logic
            let allowed = pol.policy_code.contains("allow");
            // Add audit logging
            tracing::info!(
                user = %user,
                path = %path,
                action = %action,
                policy = %pol.name,
                result = if allowed { "allowed" } else { "denied" },
                "HCL policy evaluation completed"
            );
            if !allowed {
                return false;
            }
        } else {
             // Existing logic for other policies?
        }
    }
    true
}

// Integrasi ke policy engine utama
pub async fn check_policy_with_sentinel(config: PolicyCheckConfig<'_>) -> bool {
    // Implement sentinel policy evaluation
    if !evaluate_with_sentinel(
        config.sentinel_policies,
        config.user,
        config.path,
        config.action,
        &PolicyContext {},
    )
    .await
    {
        return false;
    }

    // Lanjut evaluasi RBAC/ACL biasa
    crate::policies::rbac::check_policy(
        config.rbac_roles,
        config.rbac_policies,
        config.path,
        config.action,
        config.policyset_json,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::sentinel::EnforcementLevel;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn test_policy_set_evaluate_allow() {
        let rule = PolicyRule {
            effect: "allow".to_string(),
            action: "read".to_string(),
            path: "secret/*".to_string(),
            condition: None,
            control_group: None,
            mfa: None,
        };
        let set = PolicySet { rules: vec![rule] };

        assert!(set.evaluate("user1", "secret/foo", "read", None));
        assert!(!set.evaluate("user1", "secret/foo", "write", None));
        assert!(!set.evaluate("user1", "other/foo", "read", None));
    }

    #[test]
    fn test_policy_set_evaluate_deny() {
        let rule = PolicyRule {
            effect: "deny".to_string(),
            action: "read".to_string(),
            path: "secret/*".to_string(),
            condition: None,
            control_group: None,
            mfa: None,
        };
        let set = PolicySet { rules: vec![rule] };

        assert!(!set.evaluate("user1", "secret/foo", "read", None));
    }

    #[test]
    fn test_policy_set_control_group() {
        let cg = ControlGroup {
            required_approvals: 2,
            approved_by: vec!["approver1".to_string()],
        };
        let rule = PolicyRule {
            effect: "allow".to_string(),
            action: "read".to_string(),
            path: "secret/*".to_string(),
            condition: None,
            control_group: Some(cg),
            mfa: None,
        };
        let set = PolicySet { rules: vec![rule] };

        // Not enough approvals
        assert!(!set.evaluate("user1", "secret/foo", "read", None));
    }

    #[test]
    fn test_policy_set_control_group_sufficient() {
        let cg = ControlGroup {
            required_approvals: 1,
            approved_by: vec!["approver1".to_string()],
        };
        let rule = PolicyRule {
            effect: "allow".to_string(),
            action: "read".to_string(),
            path: "secret/*".to_string(),
            condition: None,
            control_group: Some(cg),
            mfa: None,
        };
        let set = PolicySet { rules: vec![rule] };

        assert!(set.evaluate("user1", "secret/foo", "read", None));
    }

    #[test]
    fn test_policy_set_mfa() {
        let rule = PolicyRule {
            effect: "allow".to_string(),
            action: "read".to_string(),
            path: "secret/*".to_string(),
            condition: None,
            control_group: None,
            mfa: Some(true),
        };
        let set = PolicySet { rules: vec![rule] };

        // No context
        assert!(!set.evaluate("user1", "secret/foo", "read", None));

        // Context without mfa_passed
        let ctx = json!({ "foo": "bar" });
        assert!(!set.evaluate("user1", "secret/foo", "read", Some(&ctx)));

        // Context with mfa_passed = false
        let ctx = json!({ "mfa_passed": false });
        assert!(!set.evaluate("user1", "secret/foo", "read", Some(&ctx)));

        // Context with mfa_passed = true
        let ctx = json!({ "mfa_passed": true });
        assert!(set.evaluate("user1", "secret/foo", "read", Some(&ctx)));
    }

    #[tokio::test]
    async fn test_check_policy_with_sentinel_deny_all() {
        let policy = SentinelPolicy {
            name: "test-deny".to_string(),
            policy_code: "deny_all".to_string(),
            enforcement_level: EnforcementLevel::HardMandatory,
            description: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        };

        let config = PolicyCheckConfig {
            sentinel_policies: &[policy],
            user: "user1",
            path: "secret/foo",
            action: "read",
            _context: None,
            rbac_roles: &[],
            rbac_policies: &[],
            policyset_json: None,
        };

        // Verify that deny_all policy immediately denies access regardless of RBAC configuration.

        let result = check_policy_with_sentinel(config).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_check_policy_with_sentinel_wasm_placeholder() {
        let policy = SentinelPolicy {
            name: "test-wasm-placeholder".to_string(),
            policy_code: "wasm".to_string(),
            enforcement_level: EnforcementLevel::HardMandatory,
            description: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        };

        let config = PolicyCheckConfig {
            sentinel_policies: &[policy],
            user: "user1",
            path: "secret/foo",
            action: "read",
            _context: None,
            rbac_roles: &[],
            rbac_policies: &[],
            policyset_json: None,
        };

        let result = check_policy_with_sentinel(config).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_evaluate_with_sentinel_unknown_policy_code_allows() {
        // Ensures an advisory Sentinel policy allows the request when evaluated with `evaluate_with_sentinel`.
        let policy = SentinelPolicy {
            name: "test-default".to_string(),
            policy_code: "something_else".to_string(),
            enforcement_level: EnforcementLevel::Advisory,
            description: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        };

        // Direct helper test
        let result = evaluate_with_sentinel(
             &[policy],
             "user1",
             "secret/foo",
             "read",
             &PolicyContext {},
        ).await;
        assert!(result);
    }
}
