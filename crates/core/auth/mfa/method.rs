use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Represents the different MFA methods supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MfaMethod {
    /// Time-based One-Time Password (TOTP)
    Totp,
    /// Email-based verification
    Email,
    /// WebAuthn (FIDO2/U2F)
    WebAuthn,
    /// Recovery codes
    Recovery,
}

impl MfaMethod {
    /// Get the string representation of the MFA method
    pub fn as_str(&self) -> &'static str {
        match self {
            MfaMethod::Totp => "totp",
            MfaMethod::Email => "email",
            MfaMethod::WebAuthn => "webauthn",
            MfaMethod::Recovery => "recovery",
        }
    }

    /// Get all available MFA methods
    pub fn all() -> Vec<MfaMethod> {
        vec![
            MfaMethod::Totp,
            MfaMethod::Email,
            MfaMethod::WebAuthn,
            MfaMethod::Recovery,
        ]
    }
}

impl fmt::Display for MfaMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for MfaMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "totp" => Ok(MfaMethod::Totp),
            "email" => Ok(MfaMethod::Email),
            "webauthn" => Ok(MfaMethod::WebAuthn),
            "recovery" => Ok(MfaMethod::Recovery),
            _ => Err(format!("Invalid MFA method: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_method_serialization() {
        assert_eq!(MfaMethod::Totp.to_string(), "totp");
        assert_eq!(MfaMethod::Email.to_string(), "email");
        assert_eq!(MfaMethod::WebAuthn.to_string(), "webauthn");
        assert_eq!(MfaMethod::Recovery.to_string(), "recovery");
    }

    #[test]
    fn test_mfa_method_deserialization() {
        assert_eq!("totp".parse::<MfaMethod>().unwrap(), MfaMethod::Totp);
        assert_eq!("email".parse::<MfaMethod>().unwrap(), MfaMethod::Email);
        assert_eq!(
            "webauthn".parse::<MfaMethod>().unwrap(),
            MfaMethod::WebAuthn
        );
        assert_eq!(
            "recovery".parse::<MfaMethod>().unwrap(),
            MfaMethod::Recovery
        );
        assert!("invalid".parse::<MfaMethod>().is_err());
    }
}
