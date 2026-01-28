//! Password breach checking via HaveIBeenPwned API
//!
//! Uses k-anonymity model: only first 5 characters of SHA-1 hash are sent to API,
//! so the actual password is never exposed.

use sha1::{Digest, Sha1};

const HIBP_API_URL: &str = "https://api.pwnedpasswords.com/range/";

/// Result of password breach check
#[derive(Debug, Clone)]
pub enum BreachCheckResult {
    /// Password is safe (not found in breaches)
    Safe,
    /// Password was found in breaches
    Breached { count: u64 },
    /// Check failed (network error, etc.) - treated as safe to not block registration
    CheckFailed(String),
}

/// Check if a password has been exposed in data breaches using HaveIBeenPwned API.
///
/// Uses k-anonymity: only sends first 5 chars of SHA-1 hash, then checks locally.
/// This protects user privacy while still allowing breach detection.
pub async fn check_password_breach(password: &str) -> BreachCheckResult {
    // Check if breach checking is enabled (can be disabled in development)
    if std::env::var("DISABLE_BREACH_CHECK").is_ok() {
        return BreachCheckResult::Safe;
    }

    // Calculate SHA-1 hash of password
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let hash_hex = format!("{:X}", hash);

    // Split hash: first 5 chars for API, rest for local comparison
    let prefix = &hash_hex[..5];
    let suffix = &hash_hex[5..];

    // Query HIBP API
    let url = format!("{}{}", HIBP_API_URL, prefix);

    let client = match reqwest::Client::builder()
        .user_agent("Burrow-VPN-Password-Check")
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to create HTTP client for breach check: {}", e);
            return BreachCheckResult::CheckFailed(e.to_string());
        }
    };

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to query HIBP API: {}", e);
            return BreachCheckResult::CheckFailed(e.to_string());
        }
    };

    if !response.status().is_success() {
        tracing::warn!("HIBP API returned status: {}", response.status());
        return BreachCheckResult::CheckFailed(format!("API returned status {}", response.status()));
    }

    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("Failed to read HIBP API response: {}", e);
            return BreachCheckResult::CheckFailed(e.to_string());
        }
    };

    // Parse response: each line is "SUFFIX:COUNT"
    for line in body.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() == 2 {
            let response_suffix = parts[0].trim();
            if response_suffix.eq_ignore_ascii_case(suffix) {
                if let Ok(count) = parts[1].trim().parse::<u64>() {
                    tracing::info!("Password found in {} breaches", count);
                    return BreachCheckResult::Breached { count };
                }
            }
        }
    }

    BreachCheckResult::Safe
}

/// Format a warning message for breached passwords
pub fn breach_warning_message(count: u64) -> String {
    format!(
        "This password has been found in {} data breach{}. \
         It is strongly recommended to choose a different password for your security.",
        count,
        if count == 1 { "" } else { "es" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_hash() {
        let mut hasher = Sha1::new();
        hasher.update(b"password");
        let hash = hasher.finalize();
        let hash_hex = format!("{:X}", hash);

        // "password" hashes to 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        assert_eq!(hash_hex, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn test_hash_split() {
        let hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
        let prefix = &hash[..5];
        let suffix = &hash[5..];

        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }
}
