//! Background jobs for the Burrow server

use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::metrics;
use crate::ws::{emit_node_status, WsState};

/// Time after which a node is considered offline (no heartbeat)
const NODE_OFFLINE_THRESHOLD_SECONDS: i64 = 300; // 5 minutes

/// Check for offline nodes and update their status
pub async fn check_offline_nodes(pool: &SqlitePool, ws_state: &Arc<WsState>) {
    let threshold = Utc::now() - Duration::seconds(NODE_OFFLINE_THRESHOLD_SECONDS);
    let threshold_str = threshold.to_rfc3339();

    // Find nodes that are marked online but haven't sent a heartbeat recently
    let stale_nodes: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, network_id, name FROM nodes
         WHERE status = 'online' AND (last_seen IS NULL OR last_seen < ?)"
    )
    .bind(&threshold_str)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    if stale_nodes.is_empty() {
        return;
    }

    // Update status to offline
    for (node_id, network_id, node_name) in &stale_nodes {
        let result = sqlx::query("UPDATE nodes SET status = 'offline' WHERE id = ? AND status = 'online'")
            .bind(node_id)
            .execute(pool)
            .await;

        if let Ok(r) = result {
            if r.rows_affected() > 0 {
                tracing::info!("Node {} ({}) marked as offline", node_name, node_id);

                // Emit WebSocket event
                emit_node_status(ws_state, network_id, node_id, "offline", None);
            }
        }
    }

    tracing::debug!("Checked {} nodes for offline status", stale_nodes.len());
}

/// Update metrics gauges with current database counts
pub async fn update_metrics_gauges(pool: &SqlitePool) {
    // Users count
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    metrics::set_users_total(users);

    // Networks count
    let networks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM networks")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    metrics::set_networks_total(networks);

    // Nodes by status
    let online: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE status = 'online'")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let offline: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE status = 'offline'")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE status = 'pending'")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    metrics::set_nodes_by_status(online, offline, pending);

    tracing::debug!(
        "Updated metrics: users={}, networks={}, nodes(online={}, offline={}, pending={})",
        users, networks, online, offline, pending
    );
}

/// Clean up expired refresh tokens
pub async fn cleanup_expired_tokens(pool: &SqlitePool) {
    let now = Utc::now().to_rfc3339();

    // Delete expired refresh tokens
    let result = sqlx::query(
        "DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = 1"
    )
    .bind(&now)
    .execute(pool)
    .await;

    if let Ok(r) = result {
        if r.rows_affected() > 0 {
            tracing::debug!("Cleaned up {} expired refresh tokens", r.rows_affected());
        }
    }

    // Delete expired email tokens
    let result = sqlx::query(
        "DELETE FROM email_tokens WHERE expires_at < ?"
    )
    .bind(&now)
    .execute(pool)
    .await;

    if let Ok(r) = result {
        if r.rows_affected() > 0 {
            tracing::debug!("Cleaned up {} expired email tokens", r.rows_affected());
        }
    }

    // Delete old TOTP used codes (older than 3 minutes safely covers 90s TOTP window)
    let old_threshold = (Utc::now() - Duration::minutes(3)).to_rfc3339();
    let result = sqlx::query(
        "DELETE FROM totp_used_codes WHERE used_at < ?"
    )
    .bind(&old_threshold)
    .execute(pool)
    .await;

    if let Ok(r) = result {
        if r.rows_affected() > 0 {
            tracing::debug!("Cleaned up {} old TOTP codes", r.rows_affected());
        }
    }
}
