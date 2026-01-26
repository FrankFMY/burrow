//! API handlers

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use burrow_core::{Network, Node, NodeStatus, RegisterNodeRequest, RegisterNodeResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::audit::{log_event, AuditEvent, AuditEventType};
use crate::auth::Claims;
use crate::state::AppState;
use crate::ws::{emit_network_deleted, emit_node_joined, emit_node_status};

type AppResult<T> = Result<T, AppError>;

// Error handling
pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        // Log detailed error internally, return generic message to client
        tracing::error!("Internal error: {}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "An internal error occurred" })),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

// === Networks ===

#[derive(Deserialize)]
pub struct CreateNetworkRequest {
    pub name: String,
    pub cidr: Option<String>,
}

pub async fn create_network(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateNetworkRequest>,
) -> AppResult<Json<Network>> {
    // Validate network name
    let name = req.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(anyhow::anyhow!("Network name must be between 1 and 100 characters").into());
    }

    // Validate CIDR if provided
    if let Some(ref cidr) = req.cidr {
        if !is_valid_cidr(cidr) {
            return Err(anyhow::anyhow!("Invalid CIDR format. Expected: x.x.x.x/y").into());
        }
    }

    let network = Network {
        id: Uuid::new_v4(),
        name: req.name,
        cidr: req.cidr.unwrap_or_else(|| "10.100.0.0/16".to_string()),
        created_at: Utc::now(),
    };

    sqlx::query(
        "INSERT INTO networks (id, owner_id, name, cidr, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(network.id.to_string())
    .bind(&claims.sub)
    .bind(&network.name)
    .bind(&network.cidr)
    .bind(network.created_at.to_rfc3339())
    .execute(&state.db)
    .await?;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::NetworkCreated)
            .with_user(&claims.sub, &claims.email)
            .with_target("network", &network.id.to_string()),
    )
    .await;

    tracing::info!(
        "Created network: {} ({}) by {}",
        network.name,
        network.id,
        claims.email
    );
    Ok(Json(network))
}

pub async fn list_networks(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
) -> AppResult<Json<Vec<Network>>> {
    // Admins see all networks, users see only their own
    let rows = if claims.role == "admin" {
        sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT id, name, cidr, created_at FROM networks",
        )
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT id, name, cidr, created_at FROM networks WHERE owner_id = ?",
        )
        .bind(&claims.sub)
        .fetch_all(&state.db)
        .await?
    };

    let networks: Vec<Network> = rows
        .into_iter()
        .filter_map(|(id, name, cidr, created_at)| {
            Some(Network {
                id: id.parse().ok()?,
                name,
                cidr,
                created_at: created_at.parse().ok()?,
            })
        })
        .collect();

    Ok(Json(networks))
}

pub async fn delete_network(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    // Check ownership (admins can delete any)
    if claims.role != "admin" {
        let owner: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM networks WHERE id = ?")
                .bind(&id)
                .fetch_optional(&state.db)
                .await?;

        if owner.as_ref() != Some(&claims.sub) {
            return Err(anyhow::anyhow!("Not authorized to delete this network").into());
        }
    }

    // Delete related data first
    sqlx::query("DELETE FROM nodes WHERE network_id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;

    sqlx::query("DELETE FROM invites WHERE network_id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;

    // Delete network
    let result = sqlx::query("DELETE FROM networks WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(anyhow::anyhow!("Network not found").into());
    }

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::NetworkDeleted)
            .with_user(&claims.sub, &claims.email)
            .with_target("network", &id),
    )
    .await;

    tracing::info!("Deleted network {} by {}", id, claims.email);

    // Emit WebSocket event
    emit_network_deleted(&state.ws, &id);

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_network(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> AppResult<Json<Network>> {
    // Verify ownership (admins can view any)
    if claims.role != "admin" {
        let owner: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM networks WHERE id = ?")
                .bind(&id)
                .fetch_optional(&state.db)
                .await?;

        if owner.as_ref() != Some(&claims.sub) {
            return Err(anyhow::anyhow!("Not authorized to view this network").into());
        }
    }

    let row = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, name, cidr, created_at FROM networks WHERE id = ?"
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await?;

    let network = Network {
        id: row.0.parse()?,
        name: row.1,
        cidr: row.2,
        created_at: row.3.parse()?,
    };

    Ok(Json(network))
}

// === Nodes ===

pub async fn list_nodes(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(network_id): Path<String>,
) -> AppResult<Json<Vec<Node>>> {
    // Verify access to network (admins can view any)
    if claims.role != "admin" {
        let owner: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM networks WHERE id = ?")
                .bind(&network_id)
                .fetch_optional(&state.db)
                .await?;

        if owner.as_ref() != Some(&claims.sub) {
            return Err(anyhow::anyhow!("Not authorized to view nodes in this network").into());
        }
    }

    let rows = sqlx::query_as::<_, (String, String, String, String, Option<String>, String, String, Option<String>)>(
        "SELECT id, name, public_key, mesh_ip, endpoint, status, created_at, last_seen
         FROM nodes WHERE network_id = ?"
    )
    .bind(&network_id)
    .fetch_all(&state.db)
    .await?;

    let nodes: Vec<Node> = rows
        .into_iter()
        .filter_map(|(id, name, public_key, mesh_ip, endpoint, status, created_at, last_seen)| {
            Some(Node {
                id: id.parse().ok()?,
                name,
                public_key,
                mesh_ip,
                endpoint,
                status: match status.as_str() {
                    "online" => NodeStatus::Online,
                    "offline" => NodeStatus::Offline,
                    _ => NodeStatus::Pending,
                },
                created_at: created_at.parse().ok()?,
                last_seen: last_seen.and_then(|s| s.parse().ok()),
            })
        })
        .collect();

    Ok(Json(nodes))
}

// === Invites ===

#[derive(Serialize)]
pub struct InviteResponse {
    pub code: String,
    pub expires_at: String,
}

pub async fn create_invite(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Path(network_id): Path<String>,
) -> AppResult<Json<InviteResponse>> {
    // Verify ownership (admins can create invites for any network)
    if claims.role != "admin" {
        let owner: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM networks WHERE id = ?")
                .bind(&network_id)
                .fetch_optional(&state.db)
                .await?;

        if owner.as_ref() != Some(&claims.sub) {
            return Err(anyhow::anyhow!("Not authorized to create invites for this network").into());
        }
    }

    let code = generate_invite_code();
    let expires_at = Utc::now() + chrono::Duration::days(7);

    // Default max_uses to 10 to prevent unlimited invite sharing
    const DEFAULT_MAX_USES: i32 = 10;

    sqlx::query(
        "INSERT INTO invites (code, network_id, created_by, expires_at, max_uses, uses) VALUES (?, ?, ?, ?, ?, 0)"
    )
    .bind(&code)
    .bind(&network_id)
    .bind(&claims.sub)
    .bind(expires_at.to_rfc3339())
    .bind(DEFAULT_MAX_USES)
    .execute(&state.db)
    .await?;

    // Audit log
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::InviteCreated)
            .with_user(&claims.sub, &claims.email)
            .with_target("network", &network_id)
            .with_details(serde_json::json!({ "invite_code": &code })),
    )
    .await;

    tracing::info!(
        "Created invite code for network {} by {}",
        network_id,
        claims.email
    );

    Ok(Json(InviteResponse {
        code,
        expires_at: expires_at.to_rfc3339(),
    }))
}

// === Registration ===

pub async fn register_node(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterNodeRequest>,
) -> AppResult<Json<RegisterNodeResponse>> {
    // Validate node name
    let node_name = req.name.trim();
    if node_name.is_empty() || node_name.len() > 100 {
        return Err(anyhow::anyhow!("Node name must be between 1 and 100 characters").into());
    }

    // Validate public key (must be valid base64 and decode to exactly 32 bytes)
    use base64::{Engine, engine::general_purpose::STANDARD};
    let decoded_key = STANDARD.decode(&req.public_key)
        .map_err(|_| anyhow::anyhow!("Invalid base64 in public key"))?;
    if decoded_key.len() != 32 {
        return Err(anyhow::anyhow!("Public key must decode to exactly 32 bytes").into());
    }

    // Validate invite code format (alphanumeric, 8 chars)
    if req.invite_code.len() != 8 || !req.invite_code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(anyhow::anyhow!("Invalid invite code format").into());
    }

    // Verify invite code
    let invite = sqlx::query_as::<_, (String, String, Option<i32>, i32)>(
        "SELECT code, network_id, max_uses, uses FROM invites
         WHERE code = ? AND expires_at > datetime('now')"
    )
    .bind(&req.invite_code)
    .fetch_one(&state.db)
    .await
    .map_err(|_| anyhow::anyhow!("Invalid or expired invite code"))?;

    // Check if invite has reached max uses
    let max_uses = invite.2;
    let current_uses = invite.3;
    if let Some(max) = max_uses {
        if current_uses >= max {
            return Err(anyhow::anyhow!("Invite code has reached maximum uses").into());
        }
    }

    let network_id = invite.1;

    // Get network info
    let network_row = sqlx::query_as::<_, (String, String)>(
        "SELECT cidr, name FROM networks WHERE id = ?"
    )
    .bind(&network_id)
    .fetch_one(&state.db)
    .await?;

    // Allocate mesh IP
    let mesh_ip = allocate_mesh_ip(&state.db, &network_id, &network_row.0).await?;

    // Generate node secret for heartbeat authentication
    let node_secret = generate_node_secret();

    // Create node
    let node = Node {
        id: Uuid::new_v4(),
        name: req.name,
        public_key: req.public_key,
        mesh_ip: mesh_ip.clone(),
        endpoint: req.endpoint,
        status: NodeStatus::Online,
        created_at: Utc::now(),
        last_seen: Some(Utc::now()),
    };

    sqlx::query(
        "INSERT INTO nodes (id, network_id, name, public_key, mesh_ip, endpoint, status, created_at, last_seen, node_secret)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(node.id.to_string())
    .bind(&network_id)
    .bind(&node.name)
    .bind(&node.public_key)
    .bind(&node.mesh_ip)
    .bind(&node.endpoint)
    .bind("online")
    .bind(node.created_at.to_rfc3339())
    .bind(node.last_seen.map(|t| t.to_rfc3339()))
    .bind(&node_secret)
    .execute(&state.db)
    .await?;

    // Update invite uses
    sqlx::query("UPDATE invites SET uses = uses + 1 WHERE code = ?")
        .bind(&req.invite_code)
        .execute(&state.db)
        .await?;

    // Audit log - invite used
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::InviteUsed)
            .with_target("invite", &req.invite_code)
            .with_details(serde_json::json!({
                "network_id": &network_id,
                "node_id": node.id.to_string(),
                "node_name": &node.name
            })),
    )
    .await;

    // Audit log - node registered
    log_event(
        &state.db,
        AuditEvent::new(AuditEventType::NodeRegistered)
            .with_target("node", &node.id.to_string())
            .with_details(serde_json::json!({
                "network_id": &network_id,
                "name": &node.name,
                "mesh_ip": &mesh_ip
            })),
    )
    .await;

    // Get peers
    let peers = get_peers(&state.db, &network_id, &node.id.to_string()).await?;

    // Emit WebSocket event for new node
    emit_node_joined(
        &state.ws,
        &network_id,
        &node.id.to_string(),
        &node.name,
        &mesh_ip,
    );

    tracing::info!("Registered node: {} ({}) in network {}", node.name, node.id, network_id);

    Ok(Json(RegisterNodeResponse {
        node,
        network_id: network_id.clone(),
        mesh_ip,
        network_cidr: network_row.0,
        peers,
        node_secret,
    }))
}

// === Heartbeat ===

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    pub node_secret: String,
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Json(req): Json<HeartbeatRequest>,
) -> AppResult<Json<Vec<Node>>> {
    // Verify node_secret
    let (network_id, prev_status, stored_secret): (String, String, Option<String>) = sqlx::query_as(
        "SELECT network_id, status, node_secret FROM nodes WHERE id = ?"
    )
    .bind(&node_id)
    .fetch_one(&state.db)
    .await?;

    // Verify secret
    if stored_secret.as_ref() != Some(&req.node_secret) {
        return Err(anyhow::anyhow!("Invalid node secret").into());
    }

    // Update last_seen
    sqlx::query("UPDATE nodes SET last_seen = ?, status = 'online' WHERE id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(&node_id)
        .execute(&state.db)
        .await?;

    // Emit WebSocket event if status changed
    if prev_status != "online" {
        emit_node_status(&state.ws, &network_id, &node_id, "online", None);
    }

    // Return updated peer list
    let peers = get_peers(&state.db, &network_id, &node_id).await?;

    Ok(Json(peers))
}

// === Helpers ===

/// Validate CIDR format (e.g., "10.100.0.0/16")
fn is_valid_cidr(cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    // Validate IP part
    let ip_parts: Vec<&str> = parts[0].split('.').collect();
    if ip_parts.len() != 4 {
        return false;
    }

    for part in &ip_parts {
        match part.parse::<u8>() {
            Ok(_) => continue,
            Err(_) => return false,
        }
    }

    // Validate prefix length
    match parts[1].parse::<u8>() {
        Ok(prefix) => prefix <= 32,
        Err(_) => false,
    }
}

fn generate_invite_code() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn generate_node_secret() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let secret: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    format!("ns_{}", secret)
}

async fn allocate_mesh_ip(
    db: &sqlx::SqlitePool,
    network_id: &str,
    cidr: &str,
) -> anyhow::Result<String> {
    // Count existing nodes to determine next IP
    let count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE network_id = ?")
        .bind(network_id)
        .fetch_one(db)
        .await?;

    // Parse CIDR (e.g., "10.100.0.0/16")
    let parts: Vec<&str> = cidr.split('/').collect();
    let base_ip = parts[0];
    let prefix_len: u32 = parts.get(1).unwrap_or(&"24").parse().unwrap_or(24);

    // Parse base IP octets
    let octets: Vec<u8> = base_ip
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();

    if octets.len() != 4 {
        anyhow::bail!("Invalid CIDR format");
    }

    // Calculate max hosts for this prefix
    let host_bits = 32 - prefix_len;
    let max_hosts = (1u32 << host_bits) - 2; // Subtract network and broadcast

    let node_num = (count + 1) as u32;
    if node_num > max_hosts {
        anyhow::bail!("Network {} has no available IP addresses", cidr);
    }

    // Convert base IP to u32, add offset, convert back (with overflow protection)
    let base_u32 = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    let new_ip_u32 = base_u32
        .checked_add(node_num)
        .ok_or_else(|| anyhow::anyhow!("IP address overflow - network {} is full", cidr))?;
    let new_octets = new_ip_u32.to_be_bytes();

    let ip = format!(
        "{}.{}.{}.{}",
        new_octets[0], new_octets[1], new_octets[2], new_octets[3]
    );

    Ok(ip)
}

async fn get_peers(
    db: &sqlx::SqlitePool,
    network_id: &str,
    exclude_node_id: &str,
) -> anyhow::Result<Vec<Node>> {
    let rows = sqlx::query_as::<_, (String, String, String, String, Option<String>, String, String, Option<String>)>(
        "SELECT id, name, public_key, mesh_ip, endpoint, status, created_at, last_seen 
         FROM nodes WHERE network_id = ? AND id != ?"
    )
    .bind(network_id)
    .bind(exclude_node_id)
    .fetch_all(db)
    .await?;

    let nodes: Vec<Node> = rows
        .into_iter()
        .filter_map(|(id, name, public_key, mesh_ip, endpoint, status, created_at, last_seen)| {
            Some(Node {
                id: id.parse().ok()?,
                name,
                public_key,
                mesh_ip,
                endpoint,
                status: match status.as_str() {
                    "online" => NodeStatus::Online,
                    "offline" => NodeStatus::Offline,
                    _ => NodeStatus::Pending,
                },
                created_at: created_at.parse().ok()?,
                last_seen: last_seen.and_then(|s| s.parse().ok()),
            })
        })
        .collect();

    Ok(nodes)
}
