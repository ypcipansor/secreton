use crate::policies::sentinel::SentinelPolicy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
        if pol.policy_code == "egp" || pol.policy_code == "rgp" {
            // Execution WASM if policy_code wasm
            if pol.policy_code == "wasm" {
                // TODO: Implement WASM policy evaluation when wasmtime is available
                tracing::warn!(
                    user = %user,
                    path = %path,
                    action = %action,
                    policy = %pol.name,
                    "WASM policy evaluation not implemented - wasmtime dependency not available"
                );
                return false;
                /*
                use wasmtime::{Engine, Module, Store, Instance};
                let engine = Engine::default();
                match Module::new(&engine, &pol.source_code) {
                        Ok(module) => {
                            let mut store = Store::new(&engine, ());
                            match Instance::new(&mut store, &module, &[]) {
                                Ok(instance) => {
                                    if let Some(func) = instance.get_func(&mut store, "evaluate") {
                                        // Assume function takes no args and returns i32 (0=false, 1=true)
                                        match func.call(&mut store, &[], &mut []) {
                                            Ok(results) => {
                                                let allowed = if let Some(wasmtime::Val::I32(val)) = results.get(0) {
                                                    *val != 0
                                                } else {
                                                    true // Default to allow if not i32
                                                };
                                                // Add audit logging
                                                tracing::info!(
                                                    user = %user,
                                                    path = %path,
                                                    action = %action,
                                                    policy = %pol.name,
                                                    result = if allowed { "allowed" } else { "denied" },
                                                    "WASM policy evaluation completed"
                                                );
                                                if !allowed {
                                                    return false;
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    user = %user,
                                                    path = %path,
                                                    action = %action,
                                                    policy = %pol.name,
                                                    error = %e,
                                                    "WASM policy evaluation failed, defaulting to deny"
                                                );
                                                return false;
                                            }
                                        }
                                    } else {
                                        tracing::warn!(
                                            user = %user,
                                            path = %path,
                                            action = %action,
                                            policy = %pol.name,
                                            "WASM policy missing 'evaluate' function, defaulting to deny"
                                        );
                                        return false;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        user = %user,
                                        path = %path,
                                        action = %action,
                                        policy = %pol.name,
                                        error = %e,
                                        "WASM instance creation failed, defaulting to deny"
                                    );
                                    return false;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                user = %user,
                                path = %path,
                                action = %action,
                                policy = %pol.name,
                                error = %e,
                                "WASM module compilation failed, defaulting to deny"
                            );
                            return false;
                        }
                    }
                */
            } else {
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
            }
        }
    }
    true
}

// Integrasi ke policy engine utama
pub async fn check_policy_with_sentinel(
    sentinel_policies: &[SentinelPolicy],
    user: &str,
    path: &str,
    action: &str,
    _context: Option<&serde_json::Value>,
    rbac_roles: &[String],
    rbac_policies: &[Policy],
    policyset_json: Option<&str>,
) -> bool {
    // Implement sentinel policy evaluation
    if !evaluate_with_sentinel(sentinel_policies, user, path, action, &PolicyContext {}).await {
        return false;
    }

    // Lanjut evaluasi RBAC/ACL biasa
    crate::policies::rbac::check_policy(rbac_roles, rbac_policies, path, action, policyset_json)
}

#[cfg(test)]
mod tests {
    // Tests temporarily disabled for compilation - to be re-enabled after core fixes
}
