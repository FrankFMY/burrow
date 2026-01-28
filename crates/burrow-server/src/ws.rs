//! WebSocket module for real-time updates
//!
//! Provides live status updates for nodes and networks.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::{broadcast, RwLock};

/// WebSocket event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WsEvent {
    /// Node status changed (online/offline)
    NodeStatus {
        network_id: String,
        node_id: String,
        status: String,
        endpoint: Option<String>,
    },
    /// New node joined network
    NodeJoined {
        network_id: String,
        node_id: String,
        name: String,
        mesh_ip: String,
    },
    /// Node left network
    NodeLeft {
        network_id: String,
        node_id: String,
    },
    /// Network created
    NetworkCreated {
        network_id: String,
        name: String,
    },
    /// Network deleted
    NetworkDeleted {
        network_id: String,
    },
    /// Ping (keep-alive)
    Ping,
    /// Pong response
    Pong,
    /// Error message
    Error {
        message: String,
    },
}

/// Query parameters for WebSocket connection
#[derive(Debug, Deserialize)]
pub struct WsQuery {
    /// API token for authentication
    pub token: Option<String>,
    /// Filter by network ID (optional)
    pub network_id: Option<String>,
}

/// WebSocket state for managing connections
pub struct WsState {
    /// Broadcast channel for events
    pub tx: broadcast::Sender<WsEvent>,
    /// Connected clients per network (reserved for future per-network filtering)
    #[allow(dead_code)]
    pub clients: RwLock<HashMap<String, Vec<String>>>,
}

impl WsState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            tx,
            clients: RwLock::new(HashMap::new()),
        }
    }

    /// Broadcast an event to all subscribers
    pub fn broadcast(&self, event: WsEvent) {
        // Ignore errors (no subscribers)
        let _ = self.tx.send(event);
    }

    /// Broadcast event for a specific network
    pub fn broadcast_network(&self, network_id: &str, event: WsEvent) {
        // For now, broadcast to all; clients filter by network_id
        self.broadcast(event);
        tracing::debug!("Broadcast event for network {}", network_id);
    }
}

impl Default for WsState {
    fn default() -> Self {
        Self::new()
    }
}

use axum_extra::extract::cookie::CookieJar;
use crate::auth::{self, Claims};
use crate::auth_handlers::AUTH_COOKIE_NAME;
use crate::state::AppState;

/// WebSocket handler with required authentication
/// Supports authentication via:
/// 1. httpOnly cookie (preferred - most secure)
/// 2. Query parameter token (fallback for backwards compatibility)
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    jar: CookieJar,
    State(app_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Try to get claims from cookie first (most secure), then fallback to query param
    let claims = if let Some(cookie) = jar.get(AUTH_COOKIE_NAME) {
        // Authenticate via httpOnly cookie (preferred)
        auth::verify_token(cookie.value(), &app_state.jwt_secret).ok()
    } else if let Some(ref token) = query.token {
        // Fallback to query param (for backwards compatibility)
        // Note: Query param auth is less secure as token appears in logs
        tracing::warn!("WebSocket using query param auth - consider using cookies");
        auth::verify_token(token, &app_state.jwt_secret).ok()
    } else {
        None
    };

    // Require authentication for all WebSocket connections
    let claims = match claims {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                "Authentication required for WebSocket connection",
            )
                .into_response();
        }
    };

    // If a network_id filter is specified, verify user has access to it
    if let Some(ref network_id) = query.network_id {
        let has_access = verify_network_access(&app_state.db, &claims, network_id).await;
        if !has_access {
            return (
                StatusCode::FORBIDDEN,
                "Not authorized to access this network",
            )
                .into_response();
        }
    }

    let ws_state = app_state.ws.clone();
    ws.on_upgrade(move |socket| handle_socket(socket, query, ws_state))
        .into_response()
}

/// Verify user has access to a network
async fn verify_network_access(db: &sqlx::SqlitePool, claims: &Claims, network_id: &str) -> bool {
    // Admins have access to all networks
    if claims.role == "admin" {
        return true;
    }

    // Check if user owns the network
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT owner_id FROM networks WHERE id = ?"
    )
    .bind(network_id)
    .fetch_optional(db)
    .await
    .unwrap_or(None);

    owner.as_ref() == Some(&claims.sub)
}

async fn handle_socket(socket: WebSocket, query: WsQuery, state: Arc<WsState>) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to broadcast channel
    let mut rx = state.tx.subscribe();

    // Filter by network_id if specified
    let network_filter = query.network_id.clone();

    // Channel for sending messages from receiver task to sender task
    let (pong_tx, mut pong_rx) = tokio::sync::mpsc::channel::<WsEvent>(16);

    // Spawn task to forward broadcasts and pongs to this client
    let send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // Handle broadcast events
                event = rx.recv() => {
                    match event {
                        Ok(event) => {
                            // Filter events by network if specified
                            let should_send = match (&network_filter, &event) {
                                (Some(filter), WsEvent::NodeStatus { network_id, .. }) => network_id == filter,
                                (Some(filter), WsEvent::NodeJoined { network_id, .. }) => network_id == filter,
                                (Some(filter), WsEvent::NodeLeft { network_id, .. }) => network_id == filter,
                                (Some(filter), WsEvent::NetworkDeleted { network_id }) => network_id == filter,
                                (None, _) => true,
                                _ => true,
                            };

                            if should_send {
                                let msg = serde_json::to_string(&event).unwrap_or_default();
                                if sender.send(Message::Text(msg.into())).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Handle pong responses
                Some(event) = pong_rx.recv() => {
                    let msg = serde_json::to_string(&event).unwrap_or_default();
                    if sender.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Handle incoming messages
    while let Some(result) = receiver.next().await {
        match result {
            Ok(Message::Text(text)) => {
                // Parse incoming message
                if let Ok(event) = serde_json::from_str::<WsEvent>(&text) {
                    match event {
                        WsEvent::Ping => {
                            // Send pong via channel
                            let _ = pong_tx.send(WsEvent::Pong).await;
                            tracing::debug!("Received ping, sent pong");
                        }
                        _ => {
                            tracing::debug!("Received WS event: {:?}", event);
                        }
                    }
                }
            }
            Ok(Message::Ping(_data)) => {
                // TCP-level ping - Axum handles pong automatically
                tracing::debug!("Received WS ping (TCP level)");
            }
            Ok(Message::Close(_)) => {
                tracing::debug!("WebSocket connection closed");
                break;
            }
            Err(e) => {
                tracing::warn!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    // Clean up
    send_task.abort();
    tracing::debug!("WebSocket connection terminated");
}

/// Helper to emit node status change
pub fn emit_node_status(
    ws_state: &WsState,
    network_id: &str,
    node_id: &str,
    status: &str,
    endpoint: Option<&str>,
) {
    ws_state.broadcast_network(
        network_id,
        WsEvent::NodeStatus {
            network_id: network_id.to_string(),
            node_id: node_id.to_string(),
            status: status.to_string(),
            endpoint: endpoint.map(|s| s.to_string()),
        },
    );
}

/// Helper to emit node joined event
pub fn emit_node_joined(
    ws_state: &WsState,
    network_id: &str,
    node_id: &str,
    name: &str,
    mesh_ip: &str,
) {
    ws_state.broadcast_network(
        network_id,
        WsEvent::NodeJoined {
            network_id: network_id.to_string(),
            node_id: node_id.to_string(),
            name: name.to_string(),
            mesh_ip: mesh_ip.to_string(),
        },
    );
}

/// Helper to emit node left event
#[allow(dead_code)]
pub fn emit_node_left(ws_state: &WsState, network_id: &str, node_id: &str) {
    ws_state.broadcast_network(
        network_id,
        WsEvent::NodeLeft {
            network_id: network_id.to_string(),
            node_id: node_id.to_string(),
        },
    );
}

/// Helper to emit network deleted event
pub fn emit_network_deleted(ws_state: &WsState, network_id: &str) {
    ws_state.broadcast_network(
        network_id,
        WsEvent::NetworkDeleted {
            network_id: network_id.to_string(),
        },
    );
}
