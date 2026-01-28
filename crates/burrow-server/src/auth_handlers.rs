//! Authentication handlers

use axum::{
    extract::{Extension, Request, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::audit::{log_event, AuditEvent, AuditEventType};
use crate::auth::{self, Claims};
use crate::lockout;
use crate::password_check::{self, BreachCheckResult};
use crate::rate_limit::extract_client_ip;
use crate::state::AppState;

/// Cookie name for JWT access token
pub const AUTH_COOKIE_NAME: &str = "burrow_auth";
/// Cookie name for refresh token
pub const REFRESH_COOKIE_NAME: &str = "burrow_refresh";
/// Access token cookie max age (15 minutes)
const ACCESS_COOKIE_MAX_AGE_SECS: i64 = 15 * 60;
/// Refresh token cookie max age (7 days)
const REFRESH_COOKIE_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;

/// Create an httpOnly secure cookie for access token
fn create_auth_cookie(token: &str) -> Cookie<'static> {
    Cookie::build((AUTH_COOKIE_NAME.to_string(), token.to_string()))
        .http_only(true)
        .secure(std::env::var("INSECURE_COOKIES").is_err())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(ACCESS_COOKIE_MAX_AGE_SECS))
        .build()
}

/// Create an httpOnly secure cookie for refresh token
fn create_refresh_cookie(token: &str) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE_NAME.to_string(), token.to_string()))
        .http_only(true)
        .secure(std::env::var("INSECURE_COOKIES").is_err())
        .same_site(SameSite::Strict)
        .path("/api/auth/refresh") // Only sent to refresh endpoint
        .max_age(time::Duration::seconds(REFRESH_COOKIE_MAX_AGE_SECS))
        .build()
}

/// Create a cookie that clears the auth cookie
fn clear_auth_cookie() -> Cookie<'static> {
    Cookie::build((AUTH_COOKIE_NAME.to_string(), String::new()))
        .http_only(true)
        .secure(std::env::var("INSECURE_COOKIES").is_err())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build()
}

/// Create a cookie that clears the refresh cookie
fn clear_refresh_cookie() -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE_NAME.to_string(), String::new()))
        .http_only(true)
        .secure(std::env::var("INSECURE_COOKIES").is_err())
        .same_site(SameSite::Strict)
        .path("/api/auth/refresh")
        .max_age(time::Duration::seconds(0))
        .build()
}

// === Validation helpers ===

/// Simple email validation (checks for @ and . in domain)
fn is_valid_email(email: &str) -> bool {
    let email = email.trim();
    if email.len() > 254 || email.is_empty() {
        return false;
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let (local, domain) = (parts[0], parts[1]);

    // Local part validation
    if local.is_empty() || local.len() > 64 {
        return false;
    }

    // Domain validation
    if domain.is_empty() || !domain.contains('.') || domain.len() > 253 {
        return false;
    }

    // Domain parts must not be empty
    let domain_parts: Vec<&str> = domain.split('.').collect();
    if domain_parts.iter().any(|p| p.is_empty()) {
        return false;
    }

    true
}

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
) -> Result<impl IntoResponse, AuthHandlerError> {
    // Validate email format
    if !is_valid_email(&req.email) {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Invalid email format".to_string(),
        ));
    }

    // Validate name
    if req.name.trim().is_empty() || req.name.len() > 100 {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Name must be between 1 and 100 characters".to_string(),
        ));
    }

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

    // Validate password (bcrypt has max 72 bytes limit)
    if req.password.len() < 8 || req.password.len() > 72 {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Password must be between 8 and 72 characters".to_string(),
        ));
    }

    // Password complexity: require at least one letter and one digit
    let has_letter = req.password.chars().any(|c| c.is_alphabetic());
    let has_digit = req.password.chars().any(|c| c.is_ascii_digit());
    if !has_letter || !has_digit {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Password must contain at least one letter and one number".to_string(),
        ));
    }

    // Check if password has been exposed in data breaches
    match password_check::check_password_breach(&req.password).await {
        BreachCheckResult::Breached { count } => {
            tracing::warn!(
                "Registration attempt with breached password for email: {}",
                req.email
            );
            return Err(AuthHandlerError(
                StatusCode::BAD_REQUEST,
                password_check::breach_warning_message(count),
            ));
        }
        BreachCheckResult::CheckFailed(reason) => {
            // Log but don't block registration if check fails
            tracing::warn!("Password breach check failed: {}", reason);
        }
        BreachCheckResult::Safe => {}
    }

    // Hash password
    let password_hash = auth::hash_password(&req.password)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Create user with atomic first-admin detection to prevent race conditions
    let user_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Use atomic INSERT with subquery to determine role
    // This prevents race condition where multiple users register simultaneously
    // and all get "admin" role
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name, role, created_at)
         VALUES (?, ?, ?, ?,
                 CASE WHEN (SELECT COUNT(*) FROM users) = 0 THEN 'admin' ELSE 'user' END,
                 ?)"
    )
    .bind(&user_id)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(&req.name)
    .bind(now.to_rfc3339())
    .execute(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Fetch the actual role that was assigned
    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Create token
    let token = auth::create_token(&user_id, &req.email, &role, &state.jwt_secret)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::UserRegistered)
            .with_user(&user_id, &req.email)
            .with_details(serde_json::json!({
                "name": &req.name,
                "role": &role
            })),
    )
    .await;

    tracing::info!("User registered: {} ({})", req.email, user_id);

    // Send verification email
    if let Ok(verification_token) = create_email_verification_token(&state.db, &user_id).await {
        let email_service = crate::email::create_email_service();
        let templates = crate::email::EmailTemplates::new();
        let message = templates.email_verification(&req.email, &verification_token);

        if let Err(e) = email_service.send(message).await {
            tracing::error!("Failed to send verification email to {}: {}", req.email, e);
        } else {
            tracing::info!("Verification email sent to {}", req.email);
        }
    }

    // Create httpOnly cookie for secure token storage
    let cookie = create_auth_cookie(&token);
    let cookie_header = [(header::SET_COOKIE, cookie.to_string())];

    Ok((
        cookie_header,
        Json(AuthResponse {
            token: token.clone(),
            user: UserInfo {
                id: user_id,
                email: req.email,
                name: req.name,
                role,
            },
        }),
    ))
}

/// Login user
pub async fn login(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<impl IntoResponse, AuthHandlerError> {
    // Extract IP address and User-Agent before consuming request body
    let ip_address = extract_client_ip(&request).to_string();
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Extract JSON body
    let body_bytes = axum::body::to_bytes(request.into_body(), 1024 * 16)
        .await
        .map_err(|_| AuthHandlerError(StatusCode::BAD_REQUEST, "Invalid request body".to_string()))?;

    let req: LoginRequest = serde_json::from_slice(&body_bytes)
        .map_err(|_| AuthHandlerError(StatusCode::BAD_REQUEST, "Invalid JSON".to_string()))?;

    // Check if account is locked
    if let Some(unlock_time) = lockout::check_lockout(&state.db, &req.email, &ip_address)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        let remaining_minutes = (unlock_time - Utc::now()).num_minutes().max(1);
        return Err(AuthHandlerError(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "Account temporarily locked due to too many failed login attempts. Try again in {} minutes.",
                remaining_minutes
            ),
        ));
    }

    // Find user with 2FA status and backup codes
    let user = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, i32, Option<String>)>(
        "SELECT id, email, password_hash, name, role, totp_secret, COALESCE(totp_enabled, 0), backup_codes FROM users WHERE email = ?"
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Handle user not found - record attempt and return generic error
    let user = match user {
        Some(u) => u,
        None => {
            // Record failed attempt even if user doesn't exist (prevents user enumeration timing attack)
            lockout::record_attempt(&state.db, &req.email, &ip_address, false)
                .await
                .ok();
            return Err(AuthHandlerError(StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
        }
    };

    let (user_id, email, password_hash, name, role, totp_secret, totp_enabled, backup_codes) = user;

    // Verify password
    let valid = auth::verify_password(&req.password, &password_hash)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !valid {
        // Record failed attempt
        lockout::record_attempt(&state.db, &req.email, &ip_address, false)
            .await
            .ok();

        // Audit log - failed login
        log_event(
            &state.db,
            AuditEvent::new(AuditEventType::UserLoginFailed)
                .with_user(&user_id, &req.email)
                .with_ip(&ip_address)
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

        // First try TOTP code with replay protection
        let totp_result = crate::totp::verify_code_with_replay_protection(
            &state.db, &user_id, &secret, &totp_code, &email
        ).await;

        let valid_totp = match totp_result {
            Ok(valid) => valid,
            Err(e) if e.contains("already used") => {
                // Audit log - replay attack attempt
                log_event(
                    &state.db,
                    AuditEvent::new(AuditEventType::UserLoginFailed)
                        .with_user(&user_id, &req.email)
                        .with_details(serde_json::json!({
                            "reason": "totp_replay_attack"
                        })),
                )
                .await;
                return Err(AuthHandlerError(
                    StatusCode::UNAUTHORIZED,
                    "TOTP code already used. Please wait for a new code.".to_string(),
                ));
            }
            Err(e) => return Err(AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e)),
        };

        if !valid_totp {
            // Try backup code with atomic update to prevent race conditions
            let used_backup = try_use_backup_code(&state.db, &user_id, &email, &totp_code, &backup_codes).await;

            if !used_backup {
                // Record failed attempt
                lockout::record_attempt(&state.db, &req.email, &ip_address, false)
                    .await
                    .ok();

                // Audit log - failed 2FA
                log_event(
                    &state.db,
                    AuditEvent::new(AuditEventType::UserLoginFailed)
                        .with_user(&user_id, &req.email)
                        .with_ip(&ip_address)
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

    // Clear failed attempts after successful login
    lockout::clear_failed_attempts(&state.db, &req.email, &ip_address)
        .await
        .ok();

    // Record successful login attempt
    lockout::record_attempt(&state.db, &req.email, &ip_address, true)
        .await
        .ok();

    // Update last login
    sqlx::query("UPDATE users SET last_login = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(&user_id)
        .execute(&state.db)
        .await
        .ok();

    // Create access token
    let token = auth::create_token(&user_id, &email, &role, &state.jwt_secret)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Create refresh token
    let refresh_token = create_refresh_token(&state.db, &user_id, user_agent.as_deref(), Some(&ip_address))
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Audit log - successful login
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::UserLogin)
            .with_user(&user_id, &req.email)
            .with_ip(&ip_address),
    )
    .await;

    tracing::info!("User logged in: {}", req.email);

    // Create httpOnly cookies for secure token storage
    let access_cookie = create_auth_cookie(&token);
    let refresh_cookie = create_refresh_cookie(&refresh_token);

    Ok((
        [
            (header::SET_COOKIE, access_cookie.to_string()),
            (header::SET_COOKIE, refresh_cookie.to_string()),
        ],
        Json(AuthResponse {
            token: token.clone(),
            user: UserInfo {
                id: user_id,
                email,
                name,
                role,
            },
        }),
    ))
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

    // Generate backup codes using cryptographically secure RNG
    let backup_codes: Vec<String> = {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::from_entropy();
        (0..10)
            .map(|_| {
                let code: u32 = rng.gen_range(10000000..99999999);
                format!("{:08}", code)
            })
            .collect()
    };

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

    // Verify code with replay protection
    let totp_result = totp::verify_code_with_replay_protection(
        &state.db, &claims.sub, &secret, &req.code, &claims.email
    ).await;

    match totp_result {
        Ok(true) => {}
        Ok(false) => {
            return Err(AuthHandlerError(
                StatusCode::UNAUTHORIZED,
                "Invalid verification code".to_string(),
            ));
        }
        Err(e) if e.contains("already used") => {
            return Err(AuthHandlerError(
                StatusCode::UNAUTHORIZED,
                "Code already used. Please wait for a new code.".to_string(),
            ));
        }
        Err(e) => return Err(AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e)),
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

    // Verify code with replay protection before disabling
    let totp_result = totp::verify_code_with_replay_protection(
        &state.db, &claims.sub, &secret, &req.code, &claims.email
    ).await;

    let valid = match totp_result {
        Ok(v) => v,
        Err(e) if e.contains("already used") => {
            return Err(AuthHandlerError(
                StatusCode::UNAUTHORIZED,
                "Code already used. Please wait for a new code.".to_string(),
            ));
        }
        Err(e) => return Err(AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e)),
    };

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

/// Logout user - clears auth and refresh cookies, revokes refresh tokens
pub async fn logout(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Revoke all refresh tokens for this user
    revoke_refresh_tokens(&state.db, &claims.sub).await;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::UserLogout)
            .with_user(&claims.sub, &claims.email),
    )
    .await;

    tracing::info!("User logged out: {}", claims.email);

    // Clear both auth and refresh cookies
    let access_cookie = clear_auth_cookie();
    let refresh_cookie = clear_refresh_cookie();
    (
        [
            (header::SET_COOKIE, access_cookie.to_string()),
            (header::SET_COOKIE, refresh_cookie.to_string()),
        ],
        StatusCode::NO_CONTENT,
    )
}

/// Atomically try to use a backup code with race condition protection.
/// Uses optimistic locking by re-checking backup codes during update.
async fn try_use_backup_code(
    db: &sqlx::SqlitePool,
    user_id: &str,
    email: &str,
    code: &str,
    backup_codes: &Option<String>,
) -> bool {
    let Some(codes_json) = backup_codes else {
        return false;
    };

    let Ok(codes) = serde_json::from_str::<Vec<String>>(codes_json) else {
        return false;
    };

    let Some(pos) = codes.iter().position(|c| c == code) else {
        return false;
    };

    // Remove used backup code
    let mut new_codes = codes.clone();
    new_codes.remove(pos);
    let updated_codes_json = serde_json::to_string(&new_codes).unwrap_or_default();

    // Atomic update with optimistic locking:
    // Only update if backup_codes still matches what we read (prevents race condition)
    let result = sqlx::query(
        "UPDATE users SET backup_codes = ? WHERE id = ? AND backup_codes = ?"
    )
    .bind(&updated_codes_json)
    .bind(user_id)
    .bind(codes_json)
    .execute(db)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            // Successfully used backup code
            log_event(
                db,
                AuditEvent::new(AuditEventType::SettingsChanged)
                    .with_user(user_id, email)
                    .with_details(serde_json::json!({
                        "action": "backup_code_used",
                        "remaining_codes": new_codes.len()
                    })),
            )
            .await;

            tracing::info!("Backup code used for user {}, {} codes remaining", email, new_codes.len());
            true
        }
        _ => {
            // Either DB error or race condition (backup_codes changed)
            tracing::warn!("Failed to use backup code for user {} - possible race condition", email);
            false
        }
    }
}

// ============================================================================
// Email Verification
// ============================================================================

/// Token expiration times
const EMAIL_VERIFICATION_EXPIRY_HOURS: i64 = 24;
const PASSWORD_RESET_EXPIRY_HOURS: i64 = 1;

/// Generate a secure random token
fn generate_secure_token() -> String {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    let mut rng = ChaCha20Rng::from_entropy();
    (0..64)
        .map(|_| {
            const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Create and store an email verification token
pub async fn create_email_verification_token(
    db: &sqlx::SqlitePool,
    user_id: &str,
) -> Result<String, String> {
    let token = generate_secure_token();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(EMAIL_VERIFICATION_EXPIRY_HOURS);

    sqlx::query(
        "INSERT INTO email_tokens (token, user_id, token_type, expires_at, created_at)
         VALUES (?, ?, 'verification', ?, ?)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(expires_at.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(db)
    .await
    .map_err(|e| format!("Failed to create verification token: {}", e))?;

    Ok(token)
}

/// Request types for email verification
#[derive(Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct EmailVerificationStatus {
    pub verified: bool,
}

/// Verify email endpoint
pub async fn verify_email(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<impl IntoResponse, AuthHandlerError> {
    // Find token
    let token_data = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT user_id, expires_at, used_at FROM email_tokens
         WHERE token = ? AND token_type = 'verification'",
    )
    .bind(&req.token)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| AuthHandlerError(StatusCode::BAD_REQUEST, "Invalid or expired token".to_string()))?;

    let (user_id, expires_at_str, used_at) = token_data;

    // Check if already used
    if used_at.is_some() {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Token has already been used".to_string(),
        ));
    }

    // Check expiration
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
        .map_err(|_| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, "Invalid token data".to_string()))?;

    if Utc::now() > expires_at {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Token has expired".to_string(),
        ));
    }

    // Mark token as used
    sqlx::query("UPDATE email_tokens SET used_at = ? WHERE token = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(&req.token)
        .execute(&state.db)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Update user's email_verified status
    sqlx::query("UPDATE users SET email_verified = 1 WHERE id = ?")
        .bind(&user_id)
        .execute(&state.db)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Get user email for audit log
    let user_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::SettingsChanged)
            .with_user(&user_id, &user_email)
            .with_details(serde_json::json!({ "action": "email_verified" })),
    )
    .await;

    tracing::info!("Email verified for user {}", user_email);

    Ok(Json(serde_json::json!({
        "message": "Email verified successfully"
    })))
}

/// Resend verification email
pub async fn resend_verification(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ResendVerificationRequest>,
) -> Result<impl IntoResponse, AuthHandlerError> {
    // Find user by email
    let user = sqlx::query_as::<_, (String, String, i32)>(
        "SELECT id, name, COALESCE(email_verified, 0) FROM users WHERE email = ?",
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Don't reveal if email exists
    let Some((user_id, _name, email_verified)) = user else {
        // Still return success to prevent email enumeration
        return Ok(Json(serde_json::json!({
            "message": "If the email exists and is not verified, a verification email will be sent"
        })));
    };

    if email_verified == 1 {
        return Ok(Json(serde_json::json!({
            "message": "Email is already verified"
        })));
    }

    // Check rate limit - don't send more than 1 per 5 minutes
    let recent_token: Option<String> = sqlx::query_scalar(
        "SELECT token FROM email_tokens
         WHERE user_id = ? AND token_type = 'verification'
         AND datetime(created_at) > datetime('now', '-5 minutes')
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if recent_token.is_some() {
        return Err(AuthHandlerError(
            StatusCode::TOO_MANY_REQUESTS,
            "Please wait 5 minutes before requesting another verification email".to_string(),
        ));
    }

    // Create new verification token
    let token = create_email_verification_token(&state.db, &user_id)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Send verification email
    let email_service = crate::email::create_email_service();
    let templates = crate::email::EmailTemplates::new();
    let message = templates.email_verification(&req.email, &token);

    if let Err(e) = email_service.send(message).await {
        tracing::error!("Failed to send verification email: {}", e);
        // Don't return error to user - still log and continue
    }

    tracing::info!("Verification email resent to {}", req.email);

    Ok(Json(serde_json::json!({
        "message": "If the email exists and is not verified, a verification email will be sent"
    })))
}

/// Get email verification status (requires auth)
pub async fn email_verification_status(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<EmailVerificationStatus>, AuthHandlerError> {
    let verified: i32 = sqlx::query_scalar(
        "SELECT COALESCE(email_verified, 0) FROM users WHERE id = ?",
    )
    .bind(&claims.sub)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(EmailVerificationStatus {
        verified: verified == 1,
    }))
}

// ============================================================================
// Password Reset
// ============================================================================

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

/// Create and store a password reset token
async fn create_password_reset_token(
    db: &sqlx::SqlitePool,
    user_id: &str,
) -> Result<String, String> {
    let token = generate_secure_token();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(PASSWORD_RESET_EXPIRY_HOURS);

    sqlx::query(
        "INSERT INTO email_tokens (token, user_id, token_type, expires_at, created_at)
         VALUES (?, ?, 'password_reset', ?, ?)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(expires_at.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(db)
    .await
    .map_err(|e| format!("Failed to create password reset token: {}", e))?;

    Ok(token)
}

/// Request password reset (public endpoint)
pub async fn forgot_password(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<impl IntoResponse, AuthHandlerError> {
    // Validate email format
    if !is_valid_email(&req.email) {
        // Still return generic success to prevent enumeration
        return Ok(Json(serde_json::json!({
            "message": "If the email exists, a password reset link will be sent"
        })));
    }

    // Find user by email
    let user = sqlx::query_as::<_, (String, String)>(
        "SELECT id, name FROM users WHERE email = ?",
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Don't reveal if email exists
    let Some((user_id, _name)) = user else {
        return Ok(Json(serde_json::json!({
            "message": "If the email exists, a password reset link will be sent"
        })));
    };

    // Check rate limit - don't send more than 1 per 5 minutes
    let recent_token: Option<String> = sqlx::query_scalar(
        "SELECT token FROM email_tokens
         WHERE user_id = ? AND token_type = 'password_reset'
         AND datetime(created_at) > datetime('now', '-5 minutes')
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if recent_token.is_some() {
        return Err(AuthHandlerError(
            StatusCode::TOO_MANY_REQUESTS,
            "Please wait 5 minutes before requesting another password reset".to_string(),
        ));
    }

    // Create password reset token
    let token = create_password_reset_token(&state.db, &user_id)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Send password reset email
    let email_service = crate::email::create_email_service();
    let templates = crate::email::EmailTemplates::new();
    let message = templates.password_reset(&req.email, &token);

    if let Err(e) = email_service.send(message).await {
        tracing::error!("Failed to send password reset email: {}", e);
        // Don't return error to user - still log and continue
    }

    tracing::info!("Password reset requested for {}", req.email);

    Ok(Json(serde_json::json!({
        "message": "If the email exists, a password reset link will be sent"
    })))
}

/// Reset password with token (public endpoint)
pub async fn reset_password(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<impl IntoResponse, AuthHandlerError> {
    // Validate new password
    if req.new_password.len() < 8 || req.new_password.len() > 72 {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Password must be between 8 and 72 characters".to_string(),
        ));
    }

    let has_letter = req.new_password.chars().any(|c| c.is_alphabetic());
    let has_digit = req.new_password.chars().any(|c| c.is_ascii_digit());
    if !has_letter || !has_digit {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Password must contain at least one letter and one number".to_string(),
        ));
    }

    // Check password against breach database
    match password_check::check_password_breach(&req.new_password).await {
        BreachCheckResult::Breached { count } => {
            return Err(AuthHandlerError(
                StatusCode::BAD_REQUEST,
                password_check::breach_warning_message(count),
            ));
        }
        BreachCheckResult::CheckFailed(reason) => {
            tracing::warn!("Password breach check failed during reset: {}", reason);
        }
        BreachCheckResult::Safe => {}
    }

    // Find token
    let token_data = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT user_id, expires_at, used_at FROM email_tokens
         WHERE token = ? AND token_type = 'password_reset'",
    )
    .bind(&req.token)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| AuthHandlerError(StatusCode::BAD_REQUEST, "Invalid or expired token".to_string()))?;

    let (user_id, expires_at_str, used_at) = token_data;

    // Check if already used
    if used_at.is_some() {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Token has already been used".to_string(),
        ));
    }

    // Check expiration
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
        .map_err(|_| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, "Invalid token data".to_string()))?;

    if Utc::now() > expires_at {
        return Err(AuthHandlerError(
            StatusCode::BAD_REQUEST,
            "Token has expired".to_string(),
        ));
    }

    // Mark token as used
    sqlx::query("UPDATE email_tokens SET used_at = ? WHERE token = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(&req.token)
        .execute(&state.db)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Hash new password
    let password_hash = auth::hash_password(&req.new_password)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Update password
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&password_hash)
        .bind(&user_id)
        .execute(&state.db)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Get user email for notifications
    let user_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Send password changed notification
    let email_service = crate::email::create_email_service();
    let templates = crate::email::EmailTemplates::new();
    let message = templates.password_changed(&user_email);

    if let Err(e) = email_service.send(message).await {
        tracing::error!("Failed to send password changed notification: {}", e);
    }

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::SettingsChanged)
            .with_user(&user_id, &user_email)
            .with_details(serde_json::json!({ "action": "password_reset" })),
    )
    .await;

    tracing::info!("Password reset completed for {}", user_email);

    Ok(Json(serde_json::json!({
        "message": "Password has been reset successfully"
    })))
}

// ============================================================================
// Refresh Tokens
// ============================================================================

/// Create and store a refresh token
async fn create_refresh_token(
    db: &sqlx::SqlitePool,
    user_id: &str,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
) -> Result<String, String> {
    let token = auth::generate_refresh_token();
    let token_hash = auth::hash_refresh_token(&token);
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(auth::REFRESH_TOKEN_EXPIRY_DAYS);

    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at, user_agent, ip_address)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(user_agent)
    .bind(ip_address)
    .execute(db)
    .await
    .map_err(|e| format!("Failed to create refresh token: {}", e))?;

    Ok(token)
}

/// Response type including refresh status
#[derive(Serialize)]
pub struct AuthResponseWithRefresh {
    pub token: String,
    pub user: UserInfo,
    pub expires_in: i64, // seconds until access token expires
}

/// Refresh access token endpoint
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    jar: axum_extra::extract::cookie::CookieJar,
    request: Request,
) -> Result<impl IntoResponse, AuthHandlerError> {
    let ip_address = extract_client_ip(&request).to_string();
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Get refresh token from cookie
    let refresh_token = jar.get(REFRESH_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .ok_or_else(|| AuthHandlerError(
            StatusCode::UNAUTHORIZED,
            "No refresh token provided".to_string(),
        ))?;

    let token_hash = auth::hash_refresh_token(&refresh_token);

    // Find refresh token
    let token_data = sqlx::query_as::<_, (String, String, String, i32, Option<String>)>(
        "SELECT id, user_id, expires_at, revoked, replaced_by FROM refresh_tokens WHERE token_hash = ?",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| AuthHandlerError(StatusCode::UNAUTHORIZED, "Invalid refresh token".to_string()))?;

    let (token_id, user_id, expires_at_str, revoked, replaced_by) = token_data;

    // Check if token is revoked
    if revoked == 1 {
        // Potential token theft - revoke all tokens for this user
        tracing::warn!("Revoked refresh token used, potential token theft for user {}", user_id);

        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?")
            .bind(&user_id)
            .execute(&state.db)
            .await
            .ok();

        return Err(AuthHandlerError(
            StatusCode::UNAUTHORIZED,
            "Token has been revoked. Please login again.".to_string(),
        ));
    }

    // Check if token was already replaced (replay attack)
    if replaced_by.is_some() {
        tracing::warn!("Refresh token replay detected for user {}", user_id);

        // Revoke all tokens for security
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?")
            .bind(&user_id)
            .execute(&state.db)
            .await
            .ok();

        return Err(AuthHandlerError(
            StatusCode::UNAUTHORIZED,
            "Token has been replaced. Please login again.".to_string(),
        ));
    }

    // Check expiration
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
        .map_err(|_| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, "Invalid token data".to_string()))?;

    if Utc::now() > expires_at {
        return Err(AuthHandlerError(
            StatusCode::UNAUTHORIZED,
            "Refresh token has expired. Please login again.".to_string(),
        ));
    }

    // Get user info
    let user = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, email, name, role FROM users WHERE id = ?",
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| AuthHandlerError(StatusCode::UNAUTHORIZED, "User not found".to_string()))?;

    let (_, email, name, role) = user;

    // Create new access token
    let access_token = auth::create_token(&user_id, &email, &role, &state.jwt_secret)
        .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Rotate refresh token (create new one, mark old as replaced)
    let new_refresh_token = create_refresh_token(
        &state.db,
        &user_id,
        user_agent.as_deref(),
        Some(&ip_address),
    )
    .await
    .map_err(|e| AuthHandlerError(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Mark old token as replaced
    let new_token_hash = auth::hash_refresh_token(&new_refresh_token);
    sqlx::query("UPDATE refresh_tokens SET replaced_by = ? WHERE id = ?")
        .bind(&new_token_hash)
        .bind(&token_id)
        .execute(&state.db)
        .await
        .ok();

    tracing::debug!("Token refreshed for user {}", email);

    // Set cookies
    let access_cookie = create_auth_cookie(&access_token);
    let refresh_cookie = create_refresh_cookie(&new_refresh_token);

    Ok((
        [
            (header::SET_COOKIE, access_cookie.to_string()),
            (header::SET_COOKIE, refresh_cookie.to_string()),
        ],
        Json(AuthResponseWithRefresh {
            token: access_token,
            user: UserInfo {
                id: user_id,
                email,
                name,
                role,
            },
            expires_in: auth::ACCESS_TOKEN_EXPIRY_MINUTES * 60,
        }),
    ))
}

/// Revoke all refresh tokens for the current user (called on logout)
pub async fn revoke_refresh_tokens(db: &sqlx::SqlitePool, user_id: &str) {
    sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0")
        .bind(user_id)
        .execute(db)
        .await
        .ok();
}
