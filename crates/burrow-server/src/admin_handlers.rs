//! Admin API handlers
//!
//! All endpoints require admin role authentication.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::audit::{log_event, AuditEvent, AuditEventType};
use crate::auth::Claims;
use crate::handlers::{AppError, AppResult};
use crate::state::AppState;

/// Require admin role - returns error if not admin
fn require_admin(claims: &Claims) -> AppResult<()> {
    if claims.role != "admin" {
        return Err(AppError::forbidden("Admin access required"));
    }
    Ok(())
}

// === User Management ===

#[derive(Serialize)]
pub struct AdminUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub email_verified: bool,
    pub totp_enabled: bool,
    pub created_at: String,
    pub last_login: Option<String>,
}

#[derive(Deserialize)]
pub struct ListUsersQuery {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    pub search: Option<String>,
}

#[derive(Serialize)]
pub struct ListUsersResponse {
    pub users: Vec<AdminUser>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<ListUsersQuery>,
) -> AppResult<Json<ListUsersResponse>> {
    require_admin(&claims)?;

    let offset = params.offset.unwrap_or(0).max(0);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let (users, total) = if let Some(ref search) = params.search {
        let search_pattern = format!("%{}%", search);

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE email LIKE ? OR name LIKE ?"
        )
        .bind(&search_pattern)
        .bind(&search_pattern)
        .fetch_one(&state.db)
        .await?;

        let rows = sqlx::query_as::<_, (String, String, String, String, i32, i32, String, Option<String>)>(
            "SELECT id, email, name, role, email_verified, totp_enabled, created_at, last_login
             FROM users WHERE email LIKE ? OR name LIKE ?
             ORDER BY created_at DESC LIMIT ? OFFSET ?"
        )
        .bind(&search_pattern)
        .bind(&search_pattern)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

        (rows, total)
    } else {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&state.db)
            .await?;

        let rows = sqlx::query_as::<_, (String, String, String, String, i32, i32, String, Option<String>)>(
            "SELECT id, email, name, role, email_verified, totp_enabled, created_at, last_login
             FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

        (rows, total)
    };

    let users: Vec<AdminUser> = users
        .into_iter()
        .map(|(id, email, name, role, email_verified, totp_enabled, created_at, last_login)| {
            AdminUser {
                id,
                email,
                name,
                role,
                email_verified: email_verified != 0,
                totp_enabled: totp_enabled != 0,
                created_at,
                last_login,
            }
        })
        .collect();

    Ok(Json(ListUsersResponse {
        users,
        total,
        offset,
        limit,
    }))
}

pub async fn get_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> AppResult<Json<AdminUser>> {
    require_admin(&claims)?;

    let row = sqlx::query_as::<_, (String, String, String, String, i32, i32, String, Option<String>)>(
        "SELECT id, email, name, role, email_verified, totp_enabled, created_at, last_login
         FROM users WHERE id = ?"
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await?;

    let row = row.ok_or_else(|| AppError::not_found("User not found"))?;

    Ok(Json(AdminUser {
        id: row.0,
        email: row.1,
        name: row.2,
        role: row.3,
        email_verified: row.4 != 0,
        totp_enabled: row.5 != 0,
        created_at: row.6,
        last_login: row.7,
    }))
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub role: Option<String>,
    pub email_verified: Option<bool>,
}

pub async fn update_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> AppResult<Json<AdminUser>> {
    require_admin(&claims)?;

    // Prevent self-demotion
    if user_id == claims.sub && req.role.as_deref() == Some("user") {
        return Err(AppError::bad_request("Cannot demote yourself from admin"));
    }

    // Validate role if provided
    if let Some(ref role) = req.role {
        if role != "user" && role != "admin" {
            return Err(AppError::bad_request("Role must be 'user' or 'admin'"));
        }
    }

    // Check user exists
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&state.db)
        .await?;

    if exists.is_none() {
        return Err(AppError::not_found("User not found"));
    }

    // Build update query dynamically
    let mut updates = Vec::new();
    let mut bindings: Vec<String> = Vec::new();

    if let Some(ref role) = req.role {
        updates.push("role = ?");
        bindings.push(role.clone());
    }

    if let Some(email_verified) = req.email_verified {
        updates.push("email_verified = ?");
        bindings.push(if email_verified { "1" } else { "0" }.to_string());
    }

    if updates.is_empty() {
        return Err(AppError::bad_request("No fields to update"));
    }

    let query = format!("UPDATE users SET {} WHERE id = ?", updates.join(", "));
    let mut q = sqlx::query(&query);

    for binding in &bindings {
        q = q.bind(binding);
    }
    q = q.bind(&user_id);

    q.execute(&state.db).await?;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::UserUpdated)
            .with_user(&claims.sub, &claims.email)
            .with_target("user", &user_id)
            .with_details(serde_json::json!({
                "role": req.role,
                "email_verified": req.email_verified,
            })),
    )
    .await;

    // Return updated user
    get_user(State(state), Extension(claims), Path(user_id)).await
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<String>,
) -> AppResult<StatusCode> {
    require_admin(&claims)?;

    // Prevent self-deletion
    if user_id == claims.sub {
        return Err(AppError::bad_request("Cannot delete yourself"));
    }

    // Check user exists
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&state.db)
        .await?;

    if exists.is_none() {
        return Err(AppError::not_found("User not found"));
    }

    // Delete user's related data
    sqlx::query("DELETE FROM api_keys WHERE user_id = ?")
        .bind(&user_id)
        .execute(&state.db)
        .await?;

    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
        .bind(&user_id)
        .execute(&state.db)
        .await?;

    sqlx::query("DELETE FROM email_tokens WHERE user_id = ?")
        .bind(&user_id)
        .execute(&state.db)
        .await?;

    sqlx::query("DELETE FROM totp_used_codes WHERE user_id = ?")
        .bind(&user_id)
        .execute(&state.db)
        .await?;

    // Transfer ownership of networks to the deleting admin or delete them
    sqlx::query("UPDATE networks SET owner_id = ? WHERE owner_id = ?")
        .bind(&claims.sub)
        .bind(&user_id)
        .execute(&state.db)
        .await?;

    // Delete user
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&user_id)
        .execute(&state.db)
        .await?;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::UserDeleted)
            .with_user(&claims.sub, &claims.email)
            .with_target("user", &user_id),
    )
    .await;

    tracing::info!("Admin {} deleted user {}", claims.email, user_id);

    Ok(StatusCode::NO_CONTENT)
}

// === Network Management ===

#[derive(Serialize)]
pub struct AdminNetwork {
    pub id: String,
    pub name: String,
    pub cidr: String,
    pub owner_id: Option<String>,
    pub owner_email: Option<String>,
    pub node_count: i64,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct ListNetworksQuery {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    pub search: Option<String>,
}

#[derive(Serialize)]
pub struct ListNetworksResponse {
    pub networks: Vec<AdminNetwork>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

pub async fn list_all_networks(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<ListNetworksQuery>,
) -> AppResult<Json<ListNetworksResponse>> {
    require_admin(&claims)?;

    let offset = params.offset.unwrap_or(0).max(0);
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let (networks, total) = if let Some(ref search) = params.search {
        let search_pattern = format!("%{}%", search);

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM networks WHERE name LIKE ?"
        )
        .bind(&search_pattern)
        .fetch_one(&state.db)
        .await?;

        let rows = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, String)>(
            "SELECT n.id, n.name, n.cidr, n.owner_id, u.email, n.created_at
             FROM networks n
             LEFT JOIN users u ON n.owner_id = u.id
             WHERE n.name LIKE ?
             ORDER BY n.created_at DESC LIMIT ? OFFSET ?"
        )
        .bind(&search_pattern)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

        (rows, total)
    } else {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM networks")
            .fetch_one(&state.db)
            .await?;

        let rows = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, String)>(
            "SELECT n.id, n.name, n.cidr, n.owner_id, u.email, n.created_at
             FROM networks n
             LEFT JOIN users u ON n.owner_id = u.id
             ORDER BY n.created_at DESC LIMIT ? OFFSET ?"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

        (rows, total)
    };

    // Get node counts for each network
    let mut admin_networks = Vec::new();
    for (id, name, cidr, owner_id, owner_email, created_at) in networks {
        let node_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM nodes WHERE network_id = ?"
        )
        .bind(&id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

        admin_networks.push(AdminNetwork {
            id,
            name,
            cidr,
            owner_id,
            owner_email,
            node_count,
            created_at,
        });
    }

    Ok(Json(ListNetworksResponse {
        networks: admin_networks,
        total,
        offset,
        limit,
    }))
}

// === Statistics ===

#[derive(Serialize)]
pub struct SystemStats {
    pub total_users: i64,
    pub verified_users: i64,
    pub admin_users: i64,
    pub total_networks: i64,
    pub total_nodes: i64,
    pub online_nodes: i64,
    pub offline_nodes: i64,
    pub pending_nodes: i64,
    pub active_sessions: i64,
    pub logins_today: i64,
    pub registrations_today: i64,
    pub server_version: String,
    pub uptime_seconds: u64,
}

// Store server start time
static SERVER_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub fn init_server_start_time() {
    SERVER_START.get_or_init(std::time::Instant::now);
}

pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> AppResult<Json<SystemStats>> {
    require_admin(&claims)?;

    let today = Utc::now().format("%Y-%m-%d").to_string();

    // User stats
    let total_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;

    let verified_users: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE email_verified = 1"
    )
    .fetch_one(&state.db)
    .await?;

    let admin_users: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE role = 'admin'"
    )
    .fetch_one(&state.db)
    .await?;

    // Network stats
    let total_networks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM networks")
        .fetch_one(&state.db)
        .await?;

    // Node stats
    let total_nodes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
        .fetch_one(&state.db)
        .await?;

    let online_nodes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nodes WHERE status = 'online'"
    )
    .fetch_one(&state.db)
    .await?;

    let offline_nodes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nodes WHERE status = 'offline'"
    )
    .fetch_one(&state.db)
    .await?;

    let pending_nodes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nodes WHERE status = 'pending'"
    )
    .fetch_one(&state.db)
    .await?;

    // Session stats (active refresh tokens)
    let active_sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM refresh_tokens WHERE revoked = 0 AND expires_at > datetime('now')"
    )
    .fetch_one(&state.db)
    .await?;

    // Today's activity
    let logins_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM login_attempts WHERE success = 1 AND attempted_at LIKE ?"
    )
    .bind(format!("{}%", today))
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let registrations_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE created_at LIKE ?"
    )
    .bind(format!("{}%", today))
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let uptime = SERVER_START
        .get()
        .map(|start| start.elapsed().as_secs())
        .unwrap_or(0);

    Ok(Json(SystemStats {
        total_users,
        verified_users,
        admin_users,
        total_networks,
        total_nodes,
        online_nodes,
        offline_nodes,
        pending_nodes,
        active_sessions,
        logins_today,
        registrations_today,
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
    }))
}

// === Audit Log ===

#[derive(Serialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub ip_address: Option<String>,
    pub details: Option<serde_json::Value>,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct ListAuditLogQuery {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    pub event_type: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Serialize)]
pub struct ListAuditLogResponse {
    pub entries: Vec<AuditLogEntry>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

pub async fn list_audit_log(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<ListAuditLogQuery>,
) -> AppResult<Json<ListAuditLogResponse>> {
    require_admin(&claims)?;

    let offset = params.offset.unwrap_or(0).max(0);
    let limit = params.limit.unwrap_or(50).clamp(1, 200);

    // Build query based on filters
    let (entries, total) = if params.event_type.is_some() || params.user_id.is_some() {
        let mut conditions = Vec::new();
        let mut bindings: Vec<String> = Vec::new();

        if let Some(ref event_type) = params.event_type {
            conditions.push("event_type = ?");
            bindings.push(event_type.clone());
        }
        if let Some(ref user_id) = params.user_id {
            conditions.push("user_id = ?");
            bindings.push(user_id.clone());
        }

        let where_clause = conditions.join(" AND ");

        let count_query = format!("SELECT COUNT(*) FROM audit_log WHERE {}", where_clause);
        let mut count_q = sqlx::query_scalar(&count_query);
        for binding in &bindings {
            count_q = count_q.bind(binding);
        }
        let total: i64 = count_q.fetch_one(&state.db).await?;

        let select_query = format!(
            "SELECT id, event_type, user_id, user_email, target_type, target_id, ip_address, details, created_at
             FROM audit_log WHERE {} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            where_clause
        );
        let mut select_q = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, String)>(&select_query);
        for binding in &bindings {
            select_q = select_q.bind(binding);
        }
        let entries = select_q
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.db)
            .await?;

        (entries, total)
    } else {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&state.db)
            .await?;

        let entries = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, String)>(
            "SELECT id, event_type, user_id, user_email, target_type, target_id, ip_address, details, created_at
             FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

        (entries, total)
    };

    let entries: Vec<AuditLogEntry> = entries
        .into_iter()
        .map(|(id, event_type, user_id, user_email, target_type, target_id, ip_address, details, created_at)| {
            AuditLogEntry {
                id,
                event_type,
                user_id,
                user_email,
                target_type,
                target_id,
                ip_address,
                details: details.and_then(|d| serde_json::from_str(&d).ok()),
                created_at,
            }
        })
        .collect();

    Ok(Json(ListAuditLogResponse {
        entries,
        total,
        offset,
        limit,
    }))
}
