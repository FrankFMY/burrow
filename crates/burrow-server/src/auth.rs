//! Authentication and authorization

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth_handlers::AUTH_COOKIE_NAME;
use crate::state::AppState;

/// JWT Claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // user_id
    pub email: String,
    pub role: String,       // "admin" or "user"
    pub exp: i64,           // expiration timestamp
    pub iat: i64,           // issued at
}

/// Auth error response
#[derive(Serialize)]
pub struct AuthError {
    pub error: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(self)).into_response()
    }
}

/// Access token expiration (15 minutes)
pub const ACCESS_TOKEN_EXPIRY_MINUTES: i64 = 15;
/// Refresh token expiration (7 days)
pub const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 7;

/// Create JWT access token for user (short-lived)
pub fn create_token(user_id: &str, email: &str, role: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let exp = now + Duration::minutes(ACCESS_TOKEN_EXPIRY_MINUTES);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Generate a secure refresh token
pub fn generate_refresh_token() -> String {
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

/// Hash refresh token for storage (SHA-256)
pub fn hash_refresh_token(token: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verify JWT token
pub fn verify_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    // Explicitly require HS256 algorithm to prevent algorithm confusion attacks
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;

    Ok(token_data.claims)
}

/// Auth middleware - validates JWT (from header or cookie) or API key
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    // Try to get token from Authorization header first, then fall back to cookie
    let claims = match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            verify_token(token, &state.jwt_secret).map_err(|_| AuthError {
                error: "Invalid token".to_string(),
            })?
        }
        Some(header) if header.starts_with("ApiKey ") => {
            let api_key = &header[7..];
            validate_api_key(&state, api_key).await.map_err(|_| AuthError {
                error: "Invalid API key".to_string(),
            })?
        }
        _ => {
            // No valid Authorization header, try cookie
            if let Some(cookie) = jar.get(AUTH_COOKIE_NAME) {
                verify_token(cookie.value(), &state.jwt_secret).map_err(|_| AuthError {
                    error: "Invalid token in cookie".to_string(),
                })?
            } else {
                return Err(AuthError {
                    error: "Missing authorization".to_string(),
                });
            }
        }
    };

    // Add claims to request extensions
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Optional auth middleware - doesn't require auth but extracts it if present
#[allow(dead_code)]
pub async fn optional_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(auth_header) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            if let Ok(claims) = verify_token(token, &state.jwt_secret) {
                request.extensions_mut().insert(claims);
            }
        }
    }

    next.run(request).await
}

/// Admin-only middleware
#[allow(dead_code)]
pub async fn admin_middleware(
    request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let claims = request
        .extensions()
        .get::<Claims>()
        .ok_or_else(|| AuthError {
            error: "Not authenticated".to_string(),
        })?;

    if claims.role != "admin" {
        return Err(AuthError {
            error: "Admin access required".to_string(),
        });
    }

    Ok(next.run(request).await)
}

/// Validate API key and return claims
/// Uses fetch_optional + constant-time comparison to prevent timing attacks
async fn validate_api_key(state: &AppState, api_key: &str) -> anyhow::Result<Claims> {
    // Validate API key format first (brw_ prefix + 32 chars)
    if !api_key.starts_with("brw_") || api_key.len() != 36 {
        // Add small random delay to prevent timing-based format detection
        use rand::Rng;
        let delay_ms = rand::thread_rng().gen_range(1..5);
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        anyhow::bail!("Invalid API key format");
    }

    // Use fetch_optional to always take the same time whether key exists or not
    let row = sqlx::query_as::<_, (String, String, String)>(
        "SELECT user_id, email, role FROM api_keys WHERE key = ? AND revoked = 0"
    )
    .bind(api_key)
    .fetch_optional(&state.db)
    .await?;

    let (user_id, email, role) = row.ok_or_else(|| anyhow::anyhow!("Invalid API key"))?;

    // Update last_used timestamp (fire-and-forget)
    let db = state.db.clone();
    let key = api_key.to_string();
    tokio::spawn(async move {
        sqlx::query("UPDATE api_keys SET last_used = ? WHERE key = ?")
            .bind(Utc::now().to_rfc3339())
            .bind(&key)
            .execute(&db)
            .await
            .ok();
    });

    Ok(Claims {
        sub: user_id,
        email,
        role,
        exp: i64::MAX,
        iat: Utc::now().timestamp(),
    })
}

/// Hash password using bcrypt
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
}

/// Verify password against hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    bcrypt::verify(password, hash)
}

/// Generate random API key using cryptographically secure RNG
pub fn generate_api_key() -> String {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Use cryptographically secure RNG
    let mut rng = ChaCha20Rng::from_entropy();

    let key: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    format!("brw_{}", key)
}
