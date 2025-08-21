//! Policy definition and model

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Policy effect (allow or deny)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

impl Default for Effect {
    fn default() -> Self {
        Self::Deny // Default to deny for security
    }
}

/// Policy rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub description: String,
    pub effect: Effect,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default)]
    pub priority: i32,
}

/// Condition for policy rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Condition {
    StringEquals { key: String, value: String },
    StringNotEquals { key: String, value: String },
    StringLike { key: String, pattern: String },
    StringNotLike { key: String, pattern: String },
    NumericEquals { key: String, value: f64 },
    NumericNotEquals { key: String, value: f64 },
    NumericLessThan { key: String, value: f64 },
    NumericGreaterThan { key: String, value: f64 },
    Bool { key: String, value: bool },
    Exists { key: String },
    NotExists { key: String },
    AllOf(Vec<Condition>),
    AnyOf(Vec<Condition>),
    Not(Box<Condition>),
}

impl Condition {
    pub fn is_met(&self, context: &HashMap<String, String>) -> bool {
        match self {
            Condition::StringEquals { key, value } => 
                context.get(key).map_or(false, |v| v == value),
            Condition::StringNotEquals { key, value } => 
                context.get(key).map_or(true, |v| v != value),
            Condition::StringLike { key, pattern } => 
                context.get(key).map_or(false, |v| wildcard_match(pattern, v)),
            Condition::StringNotLike { key, pattern } => 
                context.get(key).map_or(true, |v| !wildcard_match(pattern, v)),
            Condition::NumericEquals { key, value } => 
                context.get(key).and_then(|v| v.parse::<f64>().ok())
                    .map_or(false, |v| (v - value).abs() < f64::EPSILON),
            Condition::NumericNotEquals { key, value } => 
                context.get(key).and_then(|v| v.parse::<f64>().ok())
                    .map_or(true, |v| (v - value).abs() >= f64::EPSILON),
            Condition::NumericLessThan { key, value } => 
                context.get(key).and_then(|v| v.parse::<f64>().ok())
                    .map_or(false, |v| v < *value),
            Condition::NumericGreaterThan { key, value } => 
                context.get(key).and_then(|v| v.parse::<f64>().ok())
                    .map_or(false, |v| v > *value),
            Condition::Bool { key, value } => 
                context.get(key).and_then(|v| v.parse::<bool>().ok())
                    .map_or(false, |v| v == *value),
            Condition::Exists { key } => context.contains_key(key),
            Condition::NotExists { key } => !context.contains_key(key),
            Condition::AllOf(conditions) => conditions.iter().all(|c| c.is_met(context)),
            Condition::AnyOf(conditions) => conditions.iter().any(|c| c.is_met(context)),
            Condition::Not(condition) => !condition.is_met(context),
        }
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    // Simple wildcard matching implementation
    // For production, consider using a more robust implementation
    let mut pattern_iter = pattern.chars();
    let mut value_iter = value.chars();
    
    let mut pattern_char = pattern_iter.next();
    let mut value_char = value_iter.next();
    
    let mut star_pos = None;
    let mut match_pos = 0;
    
    loop {
        match (pattern_char, value_char) {
            (Some('*'), _) => {
                star_pos = pattern_char;
                pattern_char = pattern_iter.next();
                match_pos = value.len() - value_iter.clone().count();
            }
            (Some('?'), Some(_)) => {
                pattern_char = pattern_iter.next();
                value_char = value_iter.next();
            }
            (Some(p), Some(v)) if p == v => {
                pattern_char = pattern_iter.next();
                value_char = value_iter.next();
            }
            (None, None) => return true,
            (Some('*'), None) => return true,
            _ => {
                if let Some('*') = star_pos {
                    // Backtrack
                    pattern_char = pattern_iter.next();
                    value_char = value.chars().nth(match_pos + 1);
                    match_pos += 1;
                } else {
                    return false;
                }
            }
        }
    }
}
