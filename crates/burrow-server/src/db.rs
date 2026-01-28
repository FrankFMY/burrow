//! Database operations and migrations

use anyhow::Result;
use sqlx::SqlitePool;

/// Run database migrations
pub async fn migrate(pool: &SqlitePool) -> Result<()> {
    // Core tables
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL,
            last_login TEXT
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            key TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used TEXT,
            revoked INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS networks (
            id TEXT PRIMARY KEY,
            owner_id TEXT,
            name TEXT NOT NULL,
            cidr TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY,
            network_id TEXT NOT NULL,
            name TEXT NOT NULL,
            public_key TEXT NOT NULL UNIQUE,
            mesh_ip TEXT NOT NULL,
            endpoint TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            last_seen TEXT,
            FOREIGN KEY (network_id) REFERENCES networks(id)
        );

        CREATE TABLE IF NOT EXISTS invites (
            code TEXT PRIMARY KEY,
            network_id TEXT NOT NULL,
            created_by TEXT,
            expires_at TEXT NOT NULL,
            max_uses INTEGER,
            uses INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (network_id) REFERENCES networks(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key);
        CREATE INDEX IF NOT EXISTS idx_nodes_network ON nodes(network_id);
        CREATE INDEX IF NOT EXISTS idx_nodes_public_key ON nodes(public_key);

        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            user_id TEXT,
            user_email TEXT,
            target_type TEXT,
            target_id TEXT,
            ip_address TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

        -- TOTP replay protection: store used codes
        CREATE TABLE IF NOT EXISTS totp_used_codes (
            user_id TEXT NOT NULL,
            code TEXT NOT NULL,
            used_at TEXT NOT NULL,
            PRIMARY KEY (user_id, code),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_totp_used_codes_user ON totp_used_codes(user_id);

        -- Login attempts tracking for account lockout
        CREATE TABLE IF NOT EXISTS login_attempts (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            attempted_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempted_at);

        -- Email verification tokens
        CREATE TABLE IF NOT EXISTS email_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_type TEXT NOT NULL, -- 'verification' or 'password_reset'
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_email_tokens_user ON email_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_email_tokens_type ON email_tokens(token_type);
        CREATE INDEX IF NOT EXISTS idx_email_tokens_expires ON email_tokens(expires_at);

        -- Refresh tokens for JWT token refresh
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            replaced_by TEXT, -- Points to new token if rotated
            user_agent TEXT,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
        "#,
    )
    .execute(pool)
    .await?;

    // Add 2FA columns to users table (SQLite migration)
    // Check if column exists before adding
    // PRAGMA table_info returns: (cid, name, type, notnull, dflt_value, pk)
    let columns: Vec<(i32, String, String, i32, Option<String>, i32)> =
        sqlx::query_as("PRAGMA table_info(users)")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    // Add email_verified column
    let has_email_verified = columns.iter().any(|(_, name, _, _, _, _)| name == "email_verified");
    if !has_email_verified {
        sqlx::query("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await
            .ok();
    }

    let has_totp = columns.iter().any(|(_, name, _, _, _, _)| name == "totp_secret");
    if !has_totp {
        sqlx::query("ALTER TABLE users ADD COLUMN totp_secret TEXT")
            .execute(pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE users ADD COLUMN totp_verified INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE users ADD COLUMN backup_codes TEXT")
            .execute(pool)
            .await
            .ok();
    }

    // Add node_secret column to nodes table for heartbeat authentication
    let node_columns: Vec<(i32, String, String, i32, Option<String>, i32)> =
        sqlx::query_as("PRAGMA table_info(nodes)")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let has_node_secret = node_columns.iter().any(|(_, name, _, _, _, _)| name == "node_secret");
    if !has_node_secret {
        sqlx::query("ALTER TABLE nodes ADD COLUMN node_secret TEXT")
            .execute(pool)
            .await
            .ok();
    }

    // Create index on node_secret (after column is guaranteed to exist)
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nodes_node_secret ON nodes(node_secret)")
        .execute(pool)
        .await
        .ok();

    Ok(())
}
