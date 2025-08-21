use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use tracing::{info, error};
use anyhow::Context;
use base32;
use totp_rs::{TOTP, Secret, Algorithm};
use urlencoding::encode;

use crate::{
    models::mfa::{
        MfaSetupRequest, MfaSetupResponse, MfaVerifyRequest, 
        MfaStatusResponse, MfaLoginRequest, MfaRecoveryCodesResponse,
        MfaMethod, MfaVerificationResult
    },
    AppState,
    utils::error::AppError,
};

const TOTP_ISSUER: &str = "Vault Adhyaksa";

/// Start MFA setup process
pub async fn setup_mfa(
    State(state): State<AppState>,
    user_id: String,  // Extracted from auth middleware
    Json(payload): Json<MfaSetupRequest>,
) -> Result<impl IntoResponse, AppError> {
    match payload.method {
        MfaMethod::Totp => {
            // Generate TOTP secret and provisioning URL
            let (secret, qr_code_url) = state.mfa_manager
                .generate_totp_secret(&user_id, TOTP_ISSUER)
                .await
                .map_err(|e| {
                    error!("Failed to generate TOTP secret: {:?}", e);
                    AppError::Internal(anyhow::anyhow!("Failed to generate TOTP secret"))
                })?;
            
            Ok((
                StatusCode::OK,
                Json(MfaSetupResponse {
                    qr_code_url: Some(qr_code_url),
                    secret: Some(secret),
                    webauthn_register_options: None,
                }),
            ))
        }
        MfaMethod::WebAuthn => {
            // WebAuthn setup would go here
            Err(AppError::NotImplemented("WebAuthn not implemented yet".to_string()))
        }
        MfaMethod::Email => {
            // Email MFA setup would go here
            Err(AppError::NotImplemented("Email MFA not implemented yet".to_string()))
        }
        MfaMethod::Recovery => {
            // Recovery codes are generated during initial MFA setup
            Err(AppError::BadRequest("Recovery codes are generated during MFA setup".to_string()))
        }
    }
}

/// Verify MFA setup
pub async fn verify_mfa(
    State(state): State<AppState>,
    user_id: String,  // Extracted from auth middleware
    Json(payload): Json<MfaVerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let is_valid = state.mfa_manager
        .verify_totp_code(&user_id, &payload.code)
        .await
        .map_err(|e| {
            error!("Failed to verify TOTP code: {:?}", e);
            AppError::Internal(anyhow::anyhow!("Failed to verify TOTP code"))
        })?;

    if !is_valid {
        return Err(AppError::BadRequest("Invalid verification code".to_string()));
    }

    // Enable MFA for the user
    state.mfa_manager
        .enable_mfa(&user_id, MfaMethod::Totp)
        .await
        .map_err(|e| {
            error!("Failed to enable MFA: {:?}", e);
            AppError::Internal(anyhow::anyhow!("Failed to enable MFA"))
        })?;

    // Generate recovery codes
    let recovery_codes = state.mfa_manager
        .generate_recovery_codes(&user_id)
        .await
        .map_err(|e| {
            error!("Failed to generate recovery codes: {:?}", e);
            AppError::Internal(anyhow::anyhow!("Failed to generate recovery codes"))
        })?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "recovery_codes": recovery_codes
        })),
    ))
}

/// Get MFA status for the current user
pub async fn get_mfa_status(
    State(state): State<AppState>,
    user_id: String,  // Extracted from auth middleware
) -> Result<impl IntoResponse, AppError> {
    let is_enabled = state.mfa_manager
        .is_mfa_enabled(&user_id)
        .await
        .map_err(|e| {
            error!("Failed to check MFA status: {:?}", e);
            AppError::Internal(anyhow::anyhow!("Failed to check MFA status"))
        })?;

    let method = if is_enabled {
        state.mfa_manager
            .get_mfa_method(&user_id)
            .await
            .ok()
            .map(|m| m.to_string())
    } else {
        None
    };

    Ok(Json(MfaStatusResponse {
        is_enabled,
        method,
        setup_required: !is_enabled,
        enabled_methods: if is_enabled { 
            vec![method.unwrap_or_default()] 
        } else { 
            vec![] 
        },
    }))
}

/// Disable MFA for the current user
pub async fn disable_mfa(
    State(state): State<AppState>,
    user_id: String,  // Extracted from auth middleware
) -> Result<impl IntoResponse, AppError> {
    state.mfa_manager
        .disable_mfa(&user_id)
        .await
        .map_err(|e| {
            error!("Failed to disable MFA: {:?}", e);
            AppError::Internal(anyhow::anyhow!("Failed to disable MFA"))
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get recovery codes for the current user
pub async fn get_recovery_codes(
    State(state): State<AppState>,
    user_id: String,  // Extracted from auth middleware
) -> Result<impl IntoResponse, AppError> {
    let recovery_codes = state.mfa_manager
        .get_recovery_codes(&user_id)
        .await
        .map_err(|e| {
            error!("Failed to get recovery codes: {:?}", e);
            AppError::Internal(anyhow::anyhow!("Failed to get recovery codes"))
        })?;

    Ok(Json(MfaRecoveryCodesResponse { recovery_codes }))
}

/// Generate new recovery codes (invalidates old ones)
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    user_id: String,  // Extracted from auth middleware
) -> Result<impl IntoResponse, AppError> {
    let recovery_codes = state.mfa_manager.generate_recovery_codes(&user_id, 10)
        .await
        .map_err(|e| {
            error!("Failed to regenerate recovery codes: {:?}", e);
            AppError::Internal(anyhow::anyhow!("Failed to regenerate recovery codes"))
        })?;
    
    Ok::<_, AppError>(Json(MfaRecoveryCodesResponse {
        recovery_codes,
    }))
}

/// Login with MFA
pub async fn login_with_mfa(
    State(state): State<AppState>,
    Json(payload): Json<MfaLoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    // First, verify the username and password
    let user = state.auth_manager
        .authenticate(&payload.username, &payload.password)
        .await
        .map_err(|e| {
            error!("Authentication failed: {:?}", e);
            AppError::Unauthorized("Invalid username or password".to_string())
        })?;

    // Check if MFA is enabled for this user
    let mfa_enabled = state.mfa_manager
        .is_mfa_enabled(&user.id)
        .await
        .map_err(|e| {
            error!("Failed to check MFA status: {:?}", e);
            AppError::Internal(anyhow::anyhow!("Failed to check MFA status"))
        })?;

    if !mfa_enabled {
        // If MFA is not enabled, return a token directly
        let token = state.auth_manager
            .generate_token(&user.id, &[])
            .map_err(|e| {
                error!("Failed to generate token: {:?}", e);
                AppError::Internal(anyhow::anyhow!("Failed to generate token"))
            })?;

        return Ok(Json(serde_json::json!({
            "token": token,
            "mfa_required": false
        })));
    }

    // If MFA is enabled but no code was provided, request MFA
    if payload.code.is_none() {
        return Err(AppError::MfaRequired);
    }

    // Verify the MFA code
    let code = payload.code.unwrap();
    let mfa_result = state.mfa_manager
        .verify_mfa(&user.id, &code)
        .await
        .map_err(|e| {
            error!("MFA verification failed: {:?}", e);
            AppError::Unauthorized("Invalid MFA code".to_string())
        })?;

    if !mfa_result.is_valid {
        return Err(AppError::Unauthorized("Invalid MFA code".to_string()));
    }

    // Generate token with MFA verified claim
    let token = state.auth_manager
        .generate_token(&user.id, &[("mfa_verified", "true")])
        .map_err(|e| {
            error!("Failed to generate token: {:?}", e);
            AppError::Internal(anyhow::anyhow!("Failed to generate token"))
        })?;

    Ok(Json(serde_json::json!({
        "token": token,
        "mfa_required": true
    })))
}

 
