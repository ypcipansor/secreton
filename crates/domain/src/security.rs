//! Security classification applied to secrets and to the operations performed on them.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::SecretonError;

/// Classification level, ordered from least to most restricted.
///
/// The `Ord` derive is meaningful and relied upon: `required <= granted` is the access check.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    /// No security controls required.
    Public = 0,
    /// Basic access controls.
    #[default]
    Internal = 1,
    /// Restricted access.
    Confidential = 2,
    /// Highly restricted access.
    Secret = 3,
    /// Maximum security controls.
    TopSecret = 4,
}

impl SecurityLevel {
    pub const ALL: [SecurityLevel; 5] = [
        SecurityLevel::Public,
        SecurityLevel::Internal,
        SecurityLevel::Confidential,
        SecurityLevel::Secret,
        SecurityLevel::TopSecret,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            SecurityLevel::Public => "public",
            SecurityLevel::Internal => "internal",
            SecurityLevel::Confidential => "confidential",
            SecurityLevel::Secret => "secret",
            SecurityLevel::TopSecret => "top_secret",
        }
    }

    /// Whether a principal cleared to `self` may act on data classified `required`.
    pub fn permits(&self, required: SecurityLevel) -> bool {
        *self >= required
    }
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for SecurityLevel {
    type Err = SecretonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "public" => Ok(SecurityLevel::Public),
            "internal" => Ok(SecurityLevel::Internal),
            "confidential" => Ok(SecurityLevel::Confidential),
            "secret" => Ok(SecurityLevel::Secret),
            "top_secret" => Ok(SecurityLevel::TopSecret),
            other => Err(SecretonError::InvalidInput {
                field: "security_level".to_string(),
                reason: format!("unknown security level '{other}'"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_drives_the_access_check() {
        assert!(SecurityLevel::Secret.permits(SecurityLevel::Internal));
        assert!(!SecurityLevel::Internal.permits(SecurityLevel::Secret));
        assert!(SecurityLevel::Secret.permits(SecurityLevel::Secret));
    }

    #[test]
    fn parsing_round_trips_and_tolerates_formatting() {
        for level in SecurityLevel::ALL {
            assert_eq!(level.name().parse::<SecurityLevel>().unwrap(), level);
        }
        assert_eq!(
            "  TOP-SECRET ".parse::<SecurityLevel>().unwrap(),
            SecurityLevel::TopSecret
        );
        assert!("nonsense".parse::<SecurityLevel>().is_err());
    }

    #[test]
    fn serde_uses_the_same_wire_names_as_display() {
        let json = serde_json::to_string(&SecurityLevel::TopSecret).unwrap();
        assert_eq!(json, "\"top_secret\"");
    }
}
