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
        "#,
    )
    .execute(pool)
    .await?;

    // Add 2FA columns to users table (SQLite migration)
    // Check if column exists before adding
    let columns: Vec<(String,)> = sqlx::query_as("PRAGMA table_info(users)")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let has_totp = columns.iter().any(|(name,)| name == "totp_secret");
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
    let node_columns: Vec<(String,)> = sqlx::query_as("PRAGMA table_info(nodes)")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let has_node_secret = node_columns.iter().any(|(name,)| name == "node_secret");
    if !has_node_secret {
        sqlx::query("ALTER TABLE nodes ADD COLUMN node_secret TEXT")
            .execute(pool)
            .await
            .ok();
    }

    Ok(())
}
