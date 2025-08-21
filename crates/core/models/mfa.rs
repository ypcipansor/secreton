use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum MfaMethod {
    Totp,
    Email,
    WebAuthn,
    Recovery,
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

impl std::fmt::Display for MfaMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MfaMethod::Totp => write!(f, "totp"),
            MfaMethod::Email => write!(f, "email"),
            MfaMethod::WebAuthn => write!(f, "webauthn"),
            MfaMethod::Recovery => write!(f, "recovery"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaSetupRequest {
    pub method: MfaMethod,
    pub email: Option<String>,  // Required if method is Email
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaSetupResponse {
    pub qr_code_url: Option<String>,  // For TOTP
    pub secret: Option<String>,       // For TOTP
    pub webauthn_register_options: Option<serde_json::Value>,  // For WebAuthn
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaVerifyRequest {
    pub code: String,  // TOTP code or recovery code
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaStatusResponse {
    pub is_enabled: bool,
    pub method: Option<String>,
    pub setup_required: bool,
    pub enabled_methods: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaLoginRequest {
    pub username: String,
    pub password: String,
    pub code: Option<String>,  // MFA code if MFA is enabled
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaRecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaVerificationResult {
    pub is_valid: bool,
    pub method: MfaMethod,
    pub message: Option<String>,
}
