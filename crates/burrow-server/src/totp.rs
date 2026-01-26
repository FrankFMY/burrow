//! Two-Factor Authentication (TOTP) module
//!
//! Implements RFC 6238 TOTP for secure 2FA.

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

/// Verify a TOTP code
pub fn verify_code(secret: &str, code: &str, email: &str) -> Result<bool, String> {
    let totp = create_totp(secret, email)?;
    Ok(totp.check_current(code).unwrap_or(false))
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
