//! Policy engine for evaluating access control policies

use super::*;
use std::collections::HashMap;
use thiserror::Error;

/// Error type for policy evaluation
#[derive(Error, Debug)]
pub enum PolicyEngineError {
    #[error("Policy evaluation failed: {0}")]
    EvaluationError(String),
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),
}

/// Policy engine for evaluating access control
#[derive(Default)]
pub struct PolicyEngine {
    policies: HashMap<String, Policy>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Add a policy to the engine
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.insert(policy.id.clone(), policy);
    }
    
    /// Check if a subject is allowed to perform an action on a resource
    pub fn is_allowed(
        &self,
        subject: &Subject,
        action: &str,
        resource: &str,
        context: &HashMap<String, String>,
    ) -> bool {
        let mut applicable = self.policies.values()
            .filter(|p| self.policy_applies(p, action, resource, subject, context))
            .collect::<Vec<_>>();
            
        applicable.sort_by_key(|p| std::cmp::Reverse(p.priority));
        
        for policy in applicable {
            if policy.conditions.iter().all(|c| c.is_met(context)) {
                return matches!(policy.effect, Effect::Allow);
            }
        }
        
        false // Default deny
    }
    
    fn policy_applies(
        &self,
        policy: &Policy,
        action: &str,
        resource: &str,
        _subject: &Subject,
        _context: &HashMap<String, String>,
    ) -> bool {
        policy.actions.iter().any(|a| wildcard_match(a, action)) &&
        policy.resources.iter().any(|r| wildcard_match(r, resource))
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let mut pattern_iter = pattern.chars();
    let mut value_iter = value.chars();
    let mut star_pos = None;
    let mut match_pos = 0;
    
    loop {
        match (pattern_iter.next(), value_iter.next()) {
            (Some('*'), _) => {
                star_pos = Some(pattern_iter.clone());
                match_pos = value.len() - value_iter.clone().count();
            }
            (Some('?'), Some(_)) => continue,
            (Some(p), Some(v)) if p == v => continue,
            (None, None) => return true,
            (Some('*'), None) => return true,
            _ => {
                if let Some(mut next_pat) = star_pos.take() {
                    pattern_iter = next_pat;
                    value_iter = value.chars().skip(match_pos + 1);
                    match_pos += 1;
                    continue;
                }
                return false;
            }
        }
    }
}
