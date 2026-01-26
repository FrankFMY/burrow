//! Authentication handlers

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::audit::{log_event, AuditEvent, AuditEventType};
use crate::auth::{self, Claims};
use crate::state::AppState;

// === Request/Response types ===

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    /// TOTP code for 2FA (required if 2FA is enabled)
    pub totp_code: Option<String>,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub key: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used: Option<String>,
}

// === Error handling ===

pub struct AuthHandlerError(StatusCode, String);

impl IntoResponse for AuthHandlerError {
    fn into_response(self) -> axum::response::Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

// === Handlers ===

/// Register new user
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, AuthHandlerError> {
    // Check if user exists
    let existing = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM users WHERE email = ?"
    )
    .bind(&req.email)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if existing > 0 {
        return Err(AuthHandlerError(
            StatusCode::CONFLICT,
            "Email already registered".to_string(),
        ));
    }

    // Validate password
    if req.password.len() < 8 {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Password must be at least 8 characters".to_string(),
        ));
    }

    // Hash password
    let password_hash = auth::hash_password(&req.password)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Create user
    let user_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // First user becomes admin
    let user_count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    let role = if user_count == 0 { "admin" } else { "user" };

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name, role, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&user_id)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(&req.name)
    .bind(role)
    .bind(now.to_rfc3339())
    .execute(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Create token
    let token = auth::create_token(&user_id, &req.email, role, &state.jwt_secret)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::UserRegistered)
            .with_user(&user_id, &req.email)
            .with_details(serde_json::json!({
                "name": &req.name,
                "role": role
            })),
    )
    .await;

    tracing::info!("User registered: {} ({})", req.email, user_id);

    Ok(Json(AuthResponse {
        token,
        user: UserInfo {
            id: user_id,
            email: req.email,
            name: req.name,
            role: role.to_string(),
        },
    }))
}

/// Login user
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AuthHandlerError> {
    // Find user with 2FA status and backup codes
    let user = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, i32, Option<String>)>(
        "SELECT id, email, password_hash, name, role, totp_secret, COALESCE(totp_enabled, 0), backup_codes FROM users WHERE email = ?"
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| AuthHandlerError(StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()))?;

    let (user_id, email, password_hash, name, role, totp_secret, totp_enabled, backup_codes) = user;

    // Verify password
    let valid = auth::verify_password(&req.password, &password_hash)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !valid {
        // Audit log - failed login
        log_event(
            &state.db,
            AuditEvent::new(AuditEventType::UserLoginFailed)
                .with_user(&user_id, &req.email)
                .with_details(serde_json::json!({
                    "reason": "invalid_password"
                })),
        )
        .await;

        return Err(AuthHandlerError(
            StatusCode::UNAUTHORIZED,
            "Invalid credentials".to_string(),
        ));
    }

    // Check 2FA if enabled
    if totp_enabled == 1 {
        let totp_code = req.totp_code.ok_or_else(|| {
            AuthHandlerError(
                StatusCode::UNAUTHORIZED,
                "2FA code required".to_string(),
            )
        })?;

        let secret = totp_secret.ok_or_else(|| {
            AuthHandlerError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "2FA configuration error".to_string(),
            )
        })?;

        // First try TOTP code
        let valid_totp = crate::totp::verify_code(&secret, &totp_code, &email)
            .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

        if !valid_totp {
            // Try backup code
            let mut used_backup = false;
            if let Some(ref codes_json) = backup_codes {
                if let Ok(mut codes) = serde_json::from_str::<Vec<String>>(codes_json) {
                    if let Some(pos) = codes.iter().position(|c| c == &totp_code) {
                        // Remove used backup code
                        codes.remove(pos);
                        let updated_codes = serde_json::to_string(&codes).unwrap_or_default();

                        // Update backup codes in DB
                        sqlx::query("UPDATE users SET backup_codes = ? WHERE id = ?")
                            .bind(&updated_codes)
                            .bind(&user_id)
                            .execute(&state.db)
                            .await
                            .ok();

                        used_backup = true;

                        // Audit log - backup code used
                        log_event(
                            &state.db,
                            AuditEvent::new(AuditEventType::SettingsChanged)
                                .with_user(&user_id, &email)
                                .with_details(serde_json::json!({
                                    "action": "backup_code_used",
                                    "remaining_codes": codes.len()
                                })),
                        )
                        .await;

                        tracing::info!("Backup code used for user {}, {} codes remaining", email, codes.len());
                    }
                }
            }

            if !used_backup {
                // Audit log - failed 2FA
                log_event(
                    &state.db,
                    AuditEvent::new(AuditEventType::UserLoginFailed)
                        .with_user(&user_id, &req.email)
                        .with_details(serde_json::json!({
                            "reason": "invalid_totp"
                        })),
                )
                .await;

                return Err(AuthHandlerError(
                    StatusCode::UNAUTHORIZED,
                    "Invalid 2FA code".to_string(),
                ));
            }
        }
    }

    // Update last login
    sqlx::query("UPDATE users SET last_login = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(&user_id)
        .execute(&state.db)
        .await
        .ok();

    // Create token
    let token = auth::create_token(&user_id, &email, &role, &state.jwt_secret)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log - successful login
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::UserLogin)
            .with_user(&user_id, &req.email),
    )
    .await;

    tracing::info!("User logged in: {}", req.email);

    Ok(Json(AuthResponse {
        token,
        user: UserInfo {
            id: user_id,
            email,
            name,
            role,
        },
    }))
}

/// Get current user info
pub async fn me(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<UserInfo>, AuthHandlerError> {
    let user = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, email, name, role FROM users WHERE id = ?"
    )
    .bind(&claims.sub)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(UserInfo {
        id: user.0,
        email: user.1,
        name: user.2,
        role: user.3,
    }))
}

/// Create API key
pub async fn create_api_key(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, AuthHandlerError> {
    let key_id = Uuid::new_v4().to_string();
    let api_key = auth::generate_api_key();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO api_keys (id, user_id, key, name, email, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&key_id)
    .bind(&claims.sub)
    .bind(&api_key)
    .bind(&req.name)
    .bind(&claims.email)
    .bind(&claims.role)
    .bind(now.to_rfc3339())
    .execute(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::ApiKeyCreated)
            .with_user(&claims.sub, &claims.email)
            .with_target("api_key", &key_id)
            .with_details(serde_json::json!({
                "key_name": &req.name
            })),
    )
    .await;

    tracing::info!("API key created: {} for user {}", req.name, claims.email);

    Ok(Json(ApiKeyResponse {
        id: key_id,
        name: req.name,
        key: api_key,
        created_at: now.to_rfc3339(),
    }))
}

/// List API keys
pub async fn list_api_keys(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ApiKeyInfo>>, AuthHandlerError> {
    let rows = sqlx::query_as::<_, (String, String, String, Option<String>)>(
        "SELECT id, name, created_at, last_used FROM api_keys WHERE user_id = ? AND revoked = 0"
    )
    .bind(&claims.sub)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let keys: Vec<ApiKeyInfo> = rows
        .into_iter()
        .map(|(id, name, created_at, last_used)| ApiKeyInfo {
            id,
            name,
            created_at,
            last_used,
        })
        .collect();

    Ok(Json(keys))
}

/// Revoke API key
pub async fn revoke_api_key(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(key_id): axum::extract::Path<String>,
) -> Result<StatusCode, AuthHandlerError> {
    let result = sqlx::query(
        "UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?"
    )
    .bind(&key_id)
    .bind(&claims.sub)
    .execute(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AuthHandlerError(
            StatusCode::NOT_FOUND,
            "API key not found".to_string(),
        ));
    }

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::ApiKeyRevoked)
            .with_user(&claims.sub, &claims.email)
            .with_target("api_key", &key_id),
    )
    .await;

    tracing::info!("API key revoked: {} by user {}", key_id, claims.email);

    Ok(StatusCode::NO_CONTENT)
}

// === 2FA Types ===

#[derive(Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub qr_code: String,
    pub otpauth_uri: String,
    pub backup_codes: Vec<String>,
}

#[derive(Deserialize)]
pub struct VerifyTotpRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct TotpStatusResponse {
    pub enabled: bool,
    pub verified: bool,
}

// === 2FA Handlers ===

/// Enable 2FA - generates secret and QR code
pub async fn enable_totp(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<TotpSetupResponse>, AuthHandlerError> {
    use crate::totp;

    // Check if already enabled
    let (totp_enabled,): (i32,) = sqlx::query_as(
        "SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?"
    )
    .bind(&claims.sub)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if totp_enabled == 1 {
        return Err(AuthHandlerError(
            StatusCode::CONFLICT,
            "2FA is already enabled".to_string(),
        ));
    }

    // Generate secret
    let secret = totp::generate_secret();

    // Generate QR code
    let qr_code = totp::generate_qr_code(&secret, &claims.email)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Generate otpauth URI
    let otpauth_uri = totp::get_otpauth_uri(&secret, &claims.email)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Generate backup codes
    let backup_codes: Vec<String> = (0..10)
        .map(|_| {
            use rand::Rng;
            let code: u32 = rand::thread_rng().gen_range(10000000..99999999);
            format!("{:08}", code)
        })
        .collect();

    let backup_codes_json = serde_json::to_string(&backup_codes)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Store secret (not enabled until verified)
    sqlx::query(
        "UPDATE users SET totp_secret = ?, totp_enabled = 0, totp_verified = 0, backup_codes = ? WHERE id = ?"
    )
    .bind(&secret)
    .bind(&backup_codes_json)
    .bind(&claims.sub)
    .execute(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!("2FA setup initiated for user {}", claims.email);

    Ok(Json(TotpSetupResponse {
        secret,
        qr_code,
        otpauth_uri,
        backup_codes,
    }))
}

/// Verify 2FA setup with a code from authenticator app
pub async fn verify_totp_setup(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyTotpRequest>,
) -> Result<StatusCode, AuthHandlerError> {
    use crate::totp;

    // Get stored secret
    let (totp_secret, totp_verified): (Option<String>, i32) = sqlx::query_as(
        "SELECT totp_secret, COALESCE(totp_verified, 0) FROM users WHERE id = ?"
    )
    .bind(&claims.sub)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if totp_verified == 1 {
        return Err(AuthHandlerError(
            StatusCode::CONFLICT,
            "2FA is already verified".to_string(),
        ));
    }

    let secret = totp_secret.ok_or_else(|| {
        AuthHandlerError(StatusCode::BAD_REQUEST, "2FA not set up".to_string())
    })?;

    // Verify code
    let valid = totp::verify_code(&secret, &req.code, &claims.email)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if !valid {
        return Err(AuthHandlerError(
            StatusCode::UNAUTHORIZED,
            "Invalid verification code".to_string(),
        ));
    }

    // Enable 2FA
    sqlx::query("UPDATE users SET totp_enabled = 1, totp_verified = 1 WHERE id = ?")
        .bind(&claims.sub)
        .execute(&state.db)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::SettingsChanged)
            .with_user(&claims.sub, &claims.email)
            .with_details(serde_json::json!({ "action": "2fa_enabled" })),
    )
    .await;

    tracing::info!("2FA enabled for user {}", claims.email);

    Ok(StatusCode::NO_CONTENT)
}

/// Disable 2FA
pub async fn disable_totp(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyTotpRequest>,
) -> Result<StatusCode, AuthHandlerError> {
    use crate::totp;

    // Get stored secret
    let (totp_secret, totp_enabled): (Option<String>, i32) = sqlx::query_as(
        "SELECT totp_secret, COALESCE(totp_enabled, 0) FROM users WHERE id = ?"
    )
    .bind(&claims.sub)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if totp_enabled == 0 {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "2FA is not enabled".to_string(),
        ));
    }

    let secret = totp_secret.ok_or_else(|| {
        AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, "2FA secret not found".to_string())
    })?;

    // Verify code before disabling
    let valid = totp::verify_code(&secret, &req.code, &claims.email)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if !valid {
        return Err(AuthHandlerError(
            StatusCode::UNAUTHORIZED,
            "Invalid verification code".to_string(),
        ));
    }

    // Disable 2FA
    sqlx::query(
        "UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_verified = 0, backup_codes = NULL WHERE id = ?"
    )
    .bind(&claims.sub)
    .execute(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::SettingsChanged)
            .with_user(&claims.sub, &claims.email)
            .with_details(serde_json::json!({ "action": "2fa_disabled" })),
    )
    .await;

    tracing::info!("2FA disabled for user {}", claims.email);

    Ok(StatusCode::NO_CONTENT)
}

/// Get 2FA status
pub async fn totp_status(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<TotpStatusResponse>, AuthHandlerError> {
    let (totp_enabled, totp_verified): (i32, i32) = sqlx::query_as(
        "SELECT COALESCE(totp_enabled, 0), COALESCE(totp_verified, 0) FROM users WHERE id = ?"
    )
    .bind(&claims.sub)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TotpStatusResponse {
        enabled: totp_enabled == 1,
        verified: totp_verified == 1,
    }))
}
