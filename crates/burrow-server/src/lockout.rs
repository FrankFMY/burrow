//! Account lockout protection against brute-force attacks

use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Configuration for account lockout
pub const MAX_FAILED_ATTEMPTS: i32 = 5;
pub const LOCKOUT_WINDOW_MINUTES: i64 = 15;
pub const LOCKOUT_DURATION_MINUTES: i64 = 30;

/// Record a login attempt
pub async fn record_attempt(
    db: &SqlitePool,
    email: &str,
    ip_address: &str,
    success: bool,
) -> Result<(), sqlx::Error> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO login_attempts (id, email, ip_address, success, attempted_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(email)
    .bind(ip_address)
    .bind(if success { 1 } else { 0 })
    .bind(&now)
    .execute(db)
    .await?;

    Ok(())
}

/// Check if an account is locked out
/// Returns Some(unlock_time) if locked, None if not locked
pub async fn check_lockout(
    db: &SqlitePool,
    email: &str,
    ip_address: &str,
) -> Result<Option<DateTime<Utc>>, sqlx::Error> {
    let window_start = Utc::now() - Duration::minutes(LOCKOUT_WINDOW_MINUTES);
    let window_start_str = window_start.to_rfc3339();

    // Count failed attempts from this IP for this email in the lockout window
    let failed_count: i32 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM login_attempts
        WHERE email = ?
        AND ip_address = ?
        AND success = 0
        AND attempted_at > ?
        "#,
    )
    .bind(email)
    .bind(ip_address)
    .bind(&window_start_str)
    .fetch_one(db)
    .await?;

    if failed_count >= MAX_FAILED_ATTEMPTS {
        // Get the time of the last failed attempt to calculate unlock time
        let last_attempt: Option<String> = sqlx::query_scalar(
            r#"
            SELECT attempted_at FROM login_attempts
            WHERE email = ?
            AND ip_address = ?
            AND success = 0
            AND attempted_at > ?
            ORDER BY attempted_at DESC
            LIMIT 1
            "#,
        )
        .bind(email)
        .bind(ip_address)
        .bind(&window_start_str)
        .fetch_optional(db)
        .await?;

        if let Some(last_time_str) = last_attempt {
            if let Ok(last_time) = DateTime::parse_from_rfc3339(&last_time_str) {
                let unlock_time = last_time.with_timezone(&Utc) + Duration::minutes(LOCKOUT_DURATION_MINUTES);
                if Utc::now() < unlock_time {
                    return Ok(Some(unlock_time));
                }
            }
        }
    }

    Ok(None)
}

/// Clear failed attempts for an email/IP after successful login
pub async fn clear_failed_attempts(
    db: &SqlitePool,
    email: &str,
    ip_address: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM login_attempts WHERE email = ? AND ip_address = ? AND success = 0",
    )
    .bind(email)
    .bind(ip_address)
    .execute(db)
    .await?;

    Ok(())
}

/// Cleanup old login attempts (called periodically)
pub async fn cleanup_old_attempts(db: &SqlitePool) -> Result<u64, sqlx::Error> {
    // Keep attempts for 24 hours for auditing purposes
    let cutoff = (Utc::now() - Duration::hours(24)).to_rfc3339();

    let result = sqlx::query("DELETE FROM login_attempts WHERE attempted_at < ?")
        .bind(&cutoff)
        .execute(db)
        .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockout_constants() {
        assert_eq!(MAX_FAILED_ATTEMPTS, 5);
        assert_eq!(LOCKOUT_WINDOW_MINUTES, 15);
        assert_eq!(LOCKOUT_DURATION_MINUTES, 30);
    }
}
