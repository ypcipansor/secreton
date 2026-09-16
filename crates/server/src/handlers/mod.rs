//! HTTP request handlers.
//!
//! Handlers are thin: they validate input, call a service on
//! [`Services`](secreton_engines::Services), and shape the
//! response. Business logic lives in `secreton-engines`, so the same operation can also be
//! reached from a gRPC method or a Leptos server function without duplication.

pub mod admin;
pub mod auth;
pub mod database;
pub mod health;
pub mod lifecycle;
pub mod pki;
pub mod secret;
pub mod ssh;
pub mod sys;
pub mod totp_engine;
pub mod transit;

// Re-exported so handler modules can keep importing `crate::handlers::AppState`.
// The type itself lives with the router that owns it.
pub use crate::router::AppState;

use crate::error::ApiError;
use secreton_domain::SecretonError;

/// Validate that a caller-supplied name is safe to use in a storage path.
///
/// Storage keys are built by concatenating these names, so an unchecked value is a path
/// traversal (`../`), a key collision, or an encoding ambiguity waiting to happen. This is
/// an allowlist rather than a denylist: anything not explicitly permitted is rejected.
pub fn validate_name(name: &str) -> Result<(), ApiError> {
    let reject = |reason: &str| {
        Err(ApiError(SecretonError::InvalidInput {
            field: "name".to_string(),
            reason: reason.to_string(),
        }))
    };

    if name.is_empty() {
        return reject("must not be empty");
    }
    if name.len() > 128 {
        return reject("must not exceed 128 characters");
    }
    if name.starts_with('.') || name.starts_with('-') {
        return reject("must not start with '.' or '-'");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return reject(
            "must contain only ASCII alphanumeric characters, hyphens, underscores or dots",
        );
    }
    if name.contains("..") {
        return reject("must not contain '..'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for name in ["db", "app-1", "app_1", "app.prod", "a", &"x".repeat(128)] {
            assert!(validate_name(name).is_ok(), "rejected {name:?}");
        }
    }

    #[test]
    fn rejects_path_traversal_in_every_form() {
        for name in ["..", "../etc", "a/../b", "a..b", "..a"] {
            assert!(
                validate_name(name).is_err(),
                "traversal attempt accepted: {name:?}"
            );
        }
    }

    #[test]
    fn rejects_separators_and_encodings_that_could_alias_a_key() {
        for name in ["a/b", "a\\b", "a b", "a%2fb", "a\0b", "ünïcode", "a\nb"] {
            assert!(validate_name(name).is_err(), "accepted {name:?}");
        }
    }

    #[test]
    fn rejects_empty_leading_dot_leading_dash_and_overlong() {
        assert!(validate_name("").is_err());
        assert!(validate_name(".hidden").is_err());
        assert!(validate_name("-flag").is_err());
        assert!(validate_name(&"x".repeat(129)).is_err());
    }
}
