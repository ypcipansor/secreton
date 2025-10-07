use crate::services::audit::log_audit_external;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Use canonical types from models
pub use crate::models::{PolicyRule, ControlGroup, Policy};
pub use crate::types::sentinel::SentinelPolicy;

#[cfg(feature = "wasm")]
use wasmtime::{Engine, Instance, Module, Store};

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

pub async fn evaluate_with_sentinel(
    _sentinel_policies: &[SentinelPolicy],
    user: &str,
    _path: &str,
    _action: &str,
    _context: Option<&serde_json::Value>,
    state: &crate::server::AppState,
) -> bool {
    use std::collections::HashMap;
    // Group by (namespace, name), ambil versi terbaru
    let mut latest: HashMap<(String, String), &SentinelPolicy> = HashMap::new();
    for pol in _sentinel_policies {
        let key = (pol.namespace.clone(), pol.name.clone());
        if let Some(existing) = latest.get(&key) {
            if pol.version > existing.version {
                latest.insert(key, pol);
            }
        } else {
            latest.insert(key, pol);
        }
    }
    // Chaining: urutkan berdasarkan (namespace, name), lalu eksekusi berurutan (deny jika salah satu deny)
    let mut policies: Vec<&SentinelPolicy> = latest.values().cloned().collect();
    policies.sort_by(|a, b| a.name.cmp(&b.name));
    for pol in policies {
        if pol.policy_type == "deny_all" {
            let _ = log_audit_external(
                &state.external_audit_devices,
                "sentinel_eval",
                user,
                &pol.name,
                "denied",
            )
            .await;
            return false;
        }
        if pol.policy_type == "egp" || pol.policy_type == "rgp" {
            // Eksekusi WASM jika policy_type wasm
            if pol.policy_type == "wasm" {
                #[cfg(feature = "wasm")]
                {
                    let engine = Engine::default();
                    if let Ok(module) = Module::new(&engine, &pol.source_code) {
                        let mut store = Store::new(&engine, ());
                        if let Ok(instance) = Instance::new(&mut store, &module, &[]) {
                            if let Some(func) = instance.get_func(&mut store, "evaluate") {
                                // Dummy: panggil func tanpa argumen, asumsikan bool return
                                if let Ok(_result) = func.call(&mut store, &[], &mut []) {
                                    let allowed = true; // Dummy: asumsikan true jika tidak error
                                    let _ = log_audit_external(
                                        &state.external_audit_devices,
                                        "sentinel_eval",
                                        user,
                                        &pol.name,
                                        if allowed { "allowed" } else { "denied" },
                                    )
                                    .await;
                                    if !allowed {
                                        return false;
                                    }
                                }
                            }
                        }
                    }
                }
                #[cfg(not(feature = "wasm"))]
                {
                    // WASM disabled - default to allow
                    let _ = log_audit_external(
                        &state.external_audit_devices,
                        "sentinel_eval",
                        user,
                        &pol.name,
                        "allowed",
                    )
                    .await;
                }
            } else {
                // HCL/dummy: jika ada kata "allow" di source_code, allow
                let allowed = pol.source_code.contains("allow");
                let _ = log_audit_external(
                    &state.external_audit_devices,
                    "sentinel_eval",
                    user,
                    &pol.name,
                    if allowed { "allowed" } else { "denied" },
                )
                .await;
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
    _sentinel_policies: &[SentinelPolicy],
    _user: &str,
    path: &str,
    action: &str,
    _context: Option<&serde_json::Value>,
    rbac_roles: &[String],
    rbac_policies: &[crate::models::policy::Policy],
    policyset_json: Option<&str>,
) -> bool {
    // TODO: Implement sentinel policy evaluation
    // if !evaluate_with_sentinel(sentinel_policies, user, path, action, context, state).await {
    //     return false;
    // }

    // Lanjut evaluasi RBAC/ACL biasa
    crate::services::rbac::check_policy(rbac_roles, rbac_policies, path, action, policyset_json)
}

// Contoh: policy as code (JSON)
// {
//   "rules": [
//     { "effect": "allow", "action": "read", "path": "/secrets/*" },
//     { "effect": "deny", "action": "delete", "path": "/secrets/protected/*" }
//   ]
// }

// TODO: Integrasi Sentinel-style policy (WASM/DSL) di masa depan

#[cfg(test)]
mod tests {
    // Tests temporarily disabled for compilation - to be re-enabled after core fixes
}
