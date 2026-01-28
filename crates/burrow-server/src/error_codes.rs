//! Standardized error codes for the Burrow API
//!
//! Error codes provide machine-readable error identification
//! in addition to human-readable error messages.

use serde::Serialize;

/// API error response with standardized error code
#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    /// Human-readable error message
    pub error: String,
    /// Machine-readable error code
    pub code: u32,
    /// Additional details (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: message.into(),
            code: code.as_u32(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Standardized error codes
///
/// Error code ranges:
/// - 1000-1099: Authentication errors
/// - 1100-1199: Authorization errors
/// - 1200-1299: Validation errors
/// - 1300-1399: Resource errors
/// - 1400-1499: Rate limiting errors
/// - 1500-1599: Server errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    // Authentication (1000-1099)
    /// Invalid credentials (wrong email/password)
    InvalidCredentials = 1001,
    /// Account is locked due to too many failed attempts
    AccountLocked = 1002,
    /// Email address is not verified
    EmailNotVerified = 1003,
    /// Token has expired
    TokenExpired = 1004,
    /// Token is invalid or malformed
    TokenInvalid = 1005,
    /// 2FA code is required
    TotpRequired = 1006,
    /// 2FA code is invalid
    TotpInvalid = 1007,
    /// Password does not meet requirements
    WeakPassword = 1008,
    /// Password has been found in data breaches
    BreachedPassword = 1009,
    /// Refresh token is invalid or revoked
    RefreshTokenInvalid = 1010,

    // Authorization (1100-1199)
    /// Missing authorization header/token
    MissingAuthorization = 1101,
    /// Insufficient permissions for this action
    InsufficientPermissions = 1102,
    /// Admin role required
    AdminRequired = 1103,
    /// API key is invalid or revoked
    InvalidApiKey = 1104,

    // Validation (1200-1299)
    /// Required field is missing
    MissingField = 1201,
    /// Field value is invalid
    InvalidField = 1202,
    /// Email format is invalid
    InvalidEmail = 1203,
    /// CIDR format is invalid
    InvalidCidr = 1204,
    /// Name is too long or contains invalid characters
    InvalidName = 1205,
    /// Public key format is invalid
    InvalidPublicKey = 1206,
    /// Invite code is invalid or expired
    InvalidInviteCode = 1207,

    // Resource errors (1300-1399)
    /// Requested resource was not found
    NotFound = 1301,
    /// Resource already exists (duplicate)
    AlreadyExists = 1302,
    /// Resource conflict (e.g., CIDR overlap)
    ResourceConflict = 1303,
    /// No available resources (e.g., IP addresses exhausted)
    ResourceExhausted = 1304,

    // Rate limiting (1400-1499)
    /// Too many requests
    RateLimitExceeded = 1401,
    /// Too many login attempts
    LoginRateLimitExceeded = 1402,
    /// Too many API requests
    ApiRateLimitExceeded = 1403,

    // Server errors (1500-1599)
    /// Internal server error
    InternalError = 1501,
    /// Database error
    DatabaseError = 1502,
    /// External service error (e.g., email provider)
    ExternalServiceError = 1503,
}

impl ErrorCode {
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn default_message(&self) -> &'static str {
        match self {
            // Authentication
            ErrorCode::InvalidCredentials => "Invalid email or password",
            ErrorCode::AccountLocked => "Account is temporarily locked due to too many failed login attempts",
            ErrorCode::EmailNotVerified => "Please verify your email address to continue",
            ErrorCode::TokenExpired => "Your session has expired. Please log in again",
            ErrorCode::TokenInvalid => "Invalid authentication token",
            ErrorCode::TotpRequired => "Two-factor authentication code is required",
            ErrorCode::TotpInvalid => "Invalid two-factor authentication code",
            ErrorCode::WeakPassword => "Password does not meet security requirements",
            ErrorCode::BreachedPassword => "This password has been found in data breaches. Please choose a different password",
            ErrorCode::RefreshTokenInvalid => "Session is invalid. Please log in again",

            // Authorization
            ErrorCode::MissingAuthorization => "Authorization required",
            ErrorCode::InsufficientPermissions => "You don't have permission to perform this action",
            ErrorCode::AdminRequired => "Administrator access required",
            ErrorCode::InvalidApiKey => "Invalid or revoked API key",

            // Validation
            ErrorCode::MissingField => "Required field is missing",
            ErrorCode::InvalidField => "Invalid field value",
            ErrorCode::InvalidEmail => "Invalid email address format",
            ErrorCode::InvalidCidr => "Invalid CIDR format",
            ErrorCode::InvalidName => "Invalid name",
            ErrorCode::InvalidPublicKey => "Invalid public key format",
            ErrorCode::InvalidInviteCode => "Invalid, expired, or exhausted invite code",

            // Resource
            ErrorCode::NotFound => "Requested resource not found",
            ErrorCode::AlreadyExists => "Resource already exists",
            ErrorCode::ResourceConflict => "Resource conflict",
            ErrorCode::ResourceExhausted => "No available resources",

            // Rate limiting
            ErrorCode::RateLimitExceeded => "Too many requests. Please try again later",
            ErrorCode::LoginRateLimitExceeded => "Too many login attempts. Please try again later",
            ErrorCode::ApiRateLimitExceeded => "API rate limit exceeded",

            // Server
            ErrorCode::InternalError => "An internal error occurred",
            ErrorCode::DatabaseError => "Database error",
            ErrorCode::ExternalServiceError => "External service error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_ranges() {
        // Auth codes are 1000-1099
        assert!(ErrorCode::InvalidCredentials.as_u32() >= 1000);
        assert!(ErrorCode::RefreshTokenInvalid.as_u32() < 1100);

        // Authorization codes are 1100-1199
        assert!(ErrorCode::MissingAuthorization.as_u32() >= 1100);
        assert!(ErrorCode::InvalidApiKey.as_u32() < 1200);

        // Validation codes are 1200-1299
        assert!(ErrorCode::MissingField.as_u32() >= 1200);
        assert!(ErrorCode::InvalidInviteCode.as_u32() < 1300);
    }

    #[test]
    fn test_api_error_serialization() {
        let error = ApiError::new(ErrorCode::InvalidCredentials, "Wrong password");
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"code\":1001"));
        assert!(json.contains("\"error\":\"Wrong password\""));
    }
}
