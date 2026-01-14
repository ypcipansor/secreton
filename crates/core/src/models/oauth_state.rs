//! OAuth state model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents the state of an OAuth2 transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    /// The state string, used for CSRF protection.
    pub state: String,
    /// The OAuth provider (e.g., "github", "google").
    pub provider: String,
    /// The timestamp when the state was created.
    pub created_at: DateTime<Utc>,
    /// The timestamp when the state expires.
    pub expires_at: DateTime<Utc>,
}
