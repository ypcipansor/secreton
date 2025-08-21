//! MFA API handlers

use axum::{
    extract::{Extension, Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use validator::Validate;

use crate::{
    api::{error::ApiError, AppState},
    auth::{mfa::MfaMethod, Claims},
};

/// Request to start MFA setup
#[derive(Debug, Deserialize, Validate)]
pub struct StartMfaSetupRequest {
    /// The MFA method to set up
    #[validate(required)]
    pub method: Option<MfaMethod>,
}

/// Response for MFA setup start
#[derive(Debug, Serialize)]
pub struct StartMfaSetupResponse {
    /// The MFA method being set up
    pub method: MfaMethod,
    
    /// TOTP setup data (only for TOTP method)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpSetupData>,
    
    /// Recovery codes (only on first setup)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<String>>,
}

/// TOTP setup data
#[derive(Debug, Serialize)]
pub struct TotpSetupData {
    /// The TOTP secret key (base32 encoded)
    pub secret: String,
    
    /// The provisioning URI for authenticator apps
    pub provisioning_uri: String,
    
    /// A QR code data URL for easy setup
    pub qr_code: String,
}

/// Request to verify MFA setup
#[derive(Debug, Deserialize, Validate)]
pub struct VerifyMfaRequest {
    /// The MFA method being verified
    #[validate(required)]
    pub method: Option<MfaMethod>,
    
    /// The verification code (for TOTP)
    #[validate(length(min = 6, max = 8))]
    pub code: Option<String>,
    
    /// The recovery code (for recovery flow)
    #[validate(length(min = 8, max = 16))]
    pub recovery_code: Option<String>,
}

/// Response for MFA verification
#[derive(Debug, Serialize)]
pub struct VerifyMfaResponse {
    /// Whether verification was successful
    pub success: bool,
    
    /// Recovery codes (only shown once after setup)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<String>>,
}

/// Get MFA status for the current user
pub async fn get_mfa_status(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let status = state.auth_service.get_mfa_status(&claims.sub).await?;
    Ok(axum::response::Json(status))
}

/// Start MFA setup process
pub async fn start_mfa_setup(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<StartMfaSetupRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let method = payload.method.ok_or_else(|| {
        ApiError::bad_request("MFA method is required")
    })?;

    match method {
        MfaMethod::Totp => {
            let (secret, provisioning_uri) = state
                .auth_service
                .start_totp_setup(&claims.sub, &state.config.app.name)
                .await?;
                
            // Generate QR code
            let qr_code = generate_qr_code(&provisioning_uri)?;
            
            // Generate recovery codes
            let recovery_codes = if state.auth_service.is_mfa_setup(&claims.sub).await? {
                None
            } else {
                Some(
                    state
                        .auth_service
                        .generate_recovery_codes(&claims.sub, 8)
                        .await?,
                )
            };

            Ok(axum::response::Json(StartMfaSetupResponse {
                method,
                totp: Some(TotpSetupData {
                    secret,
                    provisioning_uri,
                    qr_code,
                }),
                recovery_codes,
            }))
        }
        _ => Err(ApiError::not_implemented("This MFA method is not yet implemented")),
    }
}

/// Verify MFA setup
pub async fn verify_mfa(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyMfaRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let method = payload.method.ok_or_else(|| {
        ApiError::bad_request("MFA method is required")
    })?;

    match method {
        MfaMethod::Totp => {
            let code = payload.code.ok_or_else(|| {
                ApiError::bad_request("Verification code is required for TOTP")
            })?;

            let result = state
                .auth_service
                .verify_totp_setup(&claims.sub, &code)
                .await?;

            let recovery_codes = if result.is_first_time {
                Some(
                    state
                        .auth_service
                        .get_recovery_codes(&claims.sub)
                        .await?,
                )
            } else {
                None
            };

            Ok(axum::response::Json(VerifyMfaResponse {
                success: result.is_valid,
                recovery_codes,
            }))
        }
        _ => Err(ApiError::not_implemented("This MFA method is not yet implemented")),
    }
}

/// Generate new recovery codes
pub async fn generate_recovery_codes(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let codes = state
        .auth_service
        .regenerate_recovery_codes(&claims.sub, 8)
        .await?;
    
    Ok(axum::response::Json(codes))
}

/// Disable MFA for the current user
pub async fn disable_mfa(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    state.auth_service.disable_mfa(&claims.sub).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Helper to generate a QR code for TOTP setup
fn generate_qr_code(uri: &str) -> Result<String, ApiError> {
    use qrcode::QrCode;
    use qrcode::render::svg;
    
    let code = QrCode::new(uri.as_bytes())
        .map_err(|e| ApiError::internal_error(&format!("Failed to generate QR code: {}", e)))?;
    
    let image = code
        .render()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#000000".to_string()))
        .light_color(svg::Color("#ffffff".to_string()))
        .build();
    
    Ok(format!("data:image/svg+xml;base64,{}", base64::encode(image)))
}

/// Request to verify MFA during login
#[derive(Debug, Deserialize, Validate)]
pub struct VerifyMfaLoginRequest {
    /// The MFA method being used
    #[validate(required)]
    pub method: Option<MfaMethod>,
    
    /// The verification code (for TOTP)
    #[validate(length(min = 6, max = 8))]
    pub code: Option<String>,
    
    /// The recovery code (for recovery flow)
    #[validate(length(min = 8, max = 16))]
    pub recovery_code: Option<String>,
    
    /// The MFA token from the login response
    #[validate(required, length(equal = 64))]
    pub mfa_token: Option<String>,
}

/// Verify MFA during login
pub async fn verify_mfa_login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyMfaLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let method = payload.method.ok_or_else(|| {
        ApiError::bad_request("MFA method is required")
    })?;
    
    let mfa_token = payload.mfa_token.ok_or_else(|| {
        ApiError::bad_request("MFA token is required")
    })?;

    match method {
        MfaMethod::Totp => {
            let code = payload.code.ok_or_else(|| {
                ApiError::bad_request("Verification code is required for TOTP")
            })?;

            let result = state
                .auth_service
                .verify_totp_login(&mfa_token, &code)
                .await?;

            Ok(axum::response::Json(result))
        }
        MfaMethod::Recovery => {
            let recovery_code = payload.recovery_code.ok_or_else(|| {
                ApiError::bad_request("Recovery code is required")
            })?;

            let result = state
                .auth_service
                .verify_recovery_code_login(&mfa_token, &recovery_code)
                .await?;

            Ok(axum::response::Json(result))
        }
        _ => Err(ApiError::not_implemented("This MFA method is not yet implemented")),
    }
}
