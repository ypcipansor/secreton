//! Error handling for the Brankas API.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use secreton_errors::SecretonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use crate::{ApiResponse, ErrorDetails, ResponseMetadata};

/// API error types - now using centralized SecretonError
pub type ApiError = SecretonError;

/// Result type alias for API operations
pub type ApiResult<T> = Result<T, ApiError>;
