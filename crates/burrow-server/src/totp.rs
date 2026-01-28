//! Two-Factor Authentication (TOTP) module
//!
//! Implements RFC 6238 TOTP for secure 2FA with replay protection.

use chrono::Utc;
use sqlx::SqlitePool;
use totp_rs::{Algorithm, Secret, TOTP};

/// TOTP configuration
const TOTP_DIGITS: usize = 6;
const TOTP_STEP: u64 = 30;
const TOTP_ISSUER: &str = "Burrow VPN";

/// Generate a new TOTP secret for a user
pub fn generate_secret() -> String {
    let secret = Secret::generate_secret();
    secret.to_encoded().to_string()
}

/// Create a TOTP instance for verification
fn create_totp(secret: &str, email: &str) -> Result<TOTP, String> {
    let secret = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|e| format!("Invalid secret: {}", e))?;

    TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        1, // 1 step tolerance (30 seconds before/after)
        TOTP_STEP,
        secret,
        Some(TOTP_ISSUER.to_string()),
        email.to_string(),
    )
    .map_err(|e| format!("Failed to create TOTP: {}", e))
}

/// Verify a TOTP code (without replay protection - use verify_code_with_replay_protection for production)
#[allow(dead_code)]
pub fn verify_code(secret: &str, code: &str, email: &str) -> Result<bool, String> {
    let totp = create_totp(secret, email)?;
    Ok(totp.check_current(code).unwrap_or(false))
}

/// Verify a TOTP code with replay protection
/// Returns Ok(true) if code is valid and hasn't been used before
/// Returns Ok(false) if code is invalid
/// Returns Err if code was already used (replay attack)
pub async fn verify_code_with_replay_protection(
    pool: &SqlitePool,
    user_id: &str,
    secret: &str,
    code: &str,
    email: &str,
) -> Result<bool, String> {
    // First verify the code is valid
    let totp = create_totp(secret, email)?;
    if !totp.check_current(code).unwrap_or(false) {
        return Ok(false);
    }

    // Check if code was already used (atomic check-and-insert)
    let now = Utc::now().to_rfc3339();

    // Try to insert - if it fails due to PRIMARY KEY conflict, code was already used
    let result = sqlx::query(
        "INSERT INTO totp_used_codes (user_id, code, used_at) VALUES (?, ?, ?)"
    )
    .bind(user_id)
    .bind(code)
    .bind(&now)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            // Successfully inserted - code is valid and first use
            // Clean up old codes (older than 2 minutes - covers the 90 second window)
            let _ = sqlx::query(
                "DELETE FROM totp_used_codes WHERE user_id = ? AND used_at < datetime('now', '-2 minutes')"
            )
            .bind(user_id)
            .execute(pool)
            .await;

            Ok(true)
        }
        Err(e) => {
            // Check if it's a unique constraint violation (code already used)
            if e.to_string().contains("UNIQUE constraint") || e.to_string().contains("PRIMARY KEY") {
                Err("TOTP code already used. Please wait for a new code.".to_string())
            } else {
                Err(format!("Database error: {}", e))
            }
        }
    }
}

/// Generate the current TOTP code (for testing)
#[allow(dead_code)]
pub fn generate_code(secret: &str, email: &str) -> Result<String, String> {
    let totp = create_totp(secret, email)?;
    totp.generate_current().map_err(|e| format!("Failed to generate code: {}", e))
}

/// Get the otpauth:// URI for QR code generation
pub fn get_otpauth_uri(secret: &str, email: &str) -> Result<String, String> {
    let totp = create_totp(secret, email)?;
    Ok(totp.get_url())
}

/// Generate a QR code as base64-encoded PNG using the totp-rs built-in feature
pub fn generate_qr_code(secret: &str, email: &str) -> Result<String, String> {
    let totp = create_totp(secret, email)?;
    totp.get_qr_base64()
        .map_err(|e| format!("Failed to generate QR code: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_generation() {
        let secret = generate_secret();
        assert!(!secret.is_empty());
        // Base32 encoded secret should be at least 16 characters
        assert!(secret.len() >= 16);
    }

    #[test]
    fn test_code_verification() {
        let secret = generate_secret();
        let email = "test@example.com";

        // Generate current code
        let code = generate_code(&secret, email).unwrap();

        // Verify it
        let valid = verify_code(&secret, &code, email).unwrap();
        assert!(valid);

        // Invalid code should fail
        let invalid = verify_code(&secret, "000000", email).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_otpauth_uri() {
        let secret = generate_secret();
        let email = "test@example.com";

        let uri = get_otpauth_uri(&secret, email).unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("Burrow"));
    }

    #[test]
    fn test_qr_code_generation() {
        let secret = generate_secret();
        let email = "test@example.com";

        let qr = generate_qr_code(&secret, email).unwrap();
        // Should be valid base64
        assert!(!qr.is_empty());
    }
}
