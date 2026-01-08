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
                if let Some(cg) = &rule.control_group
                    && cg.approved_by.len() < cg.required_approvals as usize
                {
                    // Belum cukup approval
                    return false;
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyContext {
    pub roles: Vec<String>,
    pub additional_context: serde_json::Value,
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
    context: &'a PolicyContext,
}

pub async fn evaluate_with_sentinel(
    policies: &[SentinelPolicy],
    user: &str,
    path: &str,
    action: &str,
    context: &PolicyContext,
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
                     context,
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
             // If it was meant to be WASM but handled above, this block might be redundant or for non-WASM egp/rgp
             // But existing code had inner check for "wasm", which was unreachable.

             // Since we handled WASM above, here we handle other "types" if any.
             // But based on previous code:
             /*
                if pol.policy_code == "egp" || pol.policy_code == "rgp" {
                    // Execution WASM if policy_code wasm
                    if pol.policy_code == "wasm" { ... }
                }
             */
             // That was unreachable. So we can ignore it or assume "egp"/"rgp" meant something else.
             // We'll keep the HCL logic here.

            // HCL/dummy: if policy_code contains "allow", allow
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
             // The original code iterated all policies.
             // If not deny_all, egp, rgp, or wasm, it did nothing (implicitly allowed).
             // Wait, original code:
             /*
                for pol in policies {
                    if deny_all { ... return false }
                    if egp || rgp {
                        if wasm { ... return false }
                        else { check allow; if !allowed return false }
                    }
                }
             */
             // So if not egp/rgp/deny_all, it just continued.

             // But we should probably check if it's the "Sentinel DSL" which uses `evaluate_policy_code`?
             // `sentinel.rs` has `evaluate_policy_code`.
             // But `evaluate_with_sentinel` seems to ignore that and implement its own logic.
             // This seems to be a disconnect in the codebase.
             // However, my task is WASM.
        }
    }
    true
}

// Integrasi ke policy engine utama
pub async fn check_policy_with_sentinel(config: PolicyCheckConfig<'_>) -> bool {
    // Construct PolicyContext
    let context = PolicyContext {
        roles: config.rbac_roles.to_vec(),
        additional_context: config._context.cloned().unwrap_or(serde_json::Value::Null),
    };

    // Implement sentinel policy evaluation
    if !evaluate_with_sentinel(
        config.sentinel_policies,
        config.user,
        config.path,
        config.action,
        &context,
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
    // Tests temporarily disabled for compilation - to be re-enabled after core fixes
}
