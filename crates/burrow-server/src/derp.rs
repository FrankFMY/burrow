//! DERP (Designated Encrypted Relay for Packets) server
//!
//! Provides relay service when direct P2P connections fail.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Maximum DERP packet size (64KB - typical MTU for WireGuard)
const MAX_DERP_PACKET_SIZE: usize = 64 * 1024;

/// Maximum number of concurrent DERP clients (prevents resource exhaustion)
const MAX_DERP_CLIENTS: usize = 10_000;

/// Connected DERP client
struct DerpClient {
    #[allow(dead_code)]
    public_key: String,
    tx: mpsc::Sender<Vec<u8>>,
}

/// DERP relay state
pub struct DerpState {
    clients: RwLock<HashMap<String, DerpClient>>,
    db: SqlitePool,
}

impl DerpState {
    pub fn new(db: SqlitePool) -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            db,
        }
    }

    /// Verify node_secret against database using constant-time comparison
    /// Uses indexed lookup + constant-time comparison to prevent timing attacks
    pub async fn verify_node_secret(&self, secret: &str) -> bool {
        // Validate secret format first (prevents scanning attack)
        if !secret.starts_with("ns_") || secret.len() != 35 {
            return false;
        }

        // Use indexed lookup - efficient O(log n) instead of O(n)
        // SQLite will use the index on node_secret
        let stored_secret: Option<String> = sqlx::query_scalar(
            "SELECT node_secret FROM nodes WHERE node_secret = ? LIMIT 1"
        )
        .bind(secret)
        .fetch_optional(&self.db)
        .await
        .unwrap_or(None);

        // Constant-time comparison for the found secret
        // Even though SQLite already matched, we do constant-time to prevent
        // any timing leaks from the comparison itself
        if let Some(stored) = stored_secret {
            let secret_bytes = secret.as_bytes();
            let stored_bytes = stored.as_bytes();
            if stored_bytes.len() != secret_bytes.len() {
                return false;
            }
            let mut result = 0u8;
            for (a, b) in stored_bytes.iter().zip(secret_bytes.iter()) {
                result |= a ^ b;
            }
            result == 0
        } else {
            false
        }
    }
    
    async fn register(&self, public_key: String, tx: mpsc::Sender<Vec<u8>>) -> bool {
        let mut clients = self.clients.write().await;

        // Check max clients limit to prevent resource exhaustion
        if clients.len() >= MAX_DERP_CLIENTS && !clients.contains_key(&public_key) {
            tracing::warn!("DERP: Max clients reached ({}), rejecting new connection", MAX_DERP_CLIENTS);
            return false;
        }

        tracing::info!("DERP: Client registered: {}", &public_key[..8.min(public_key.len())]);
        clients.insert(public_key.clone(), DerpClient { public_key, tx });
        true
    }
    
    async fn unregister(&self, public_key: &str) {
        let mut clients = self.clients.write().await;
        clients.remove(public_key);
        tracing::info!("DERP: Client unregistered");
    }
    
    async fn relay(&self, to_key: &str, data: Vec<u8>) -> Result<(), String> {
        let clients = self.clients.read().await;
        if let Some(client) = clients.get(to_key) {
            client.tx.send(data).await.map_err(|_| "Send failed".to_string())
        } else {
            Err("Client not found".to_string())
        }
    }
    
    #[allow(dead_code)]
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }
}

/// DERP packet types
const PKT_CLIENT_INFO: u8 = 0x01;
const PKT_SEND: u8 = 0x02;
const PKT_RECV: u8 = 0x03;
const PKT_KEEPALIVE: u8 = 0x04;

/// Query params for DERP authentication
#[derive(Debug, Deserialize)]
pub struct DerpQuery {
    /// Node secret for authentication
    pub secret: Option<String>,
}

/// Handle WebSocket upgrade for DERP connection
/// Requires authentication via node_secret query parameter verified against database
pub async fn derp_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<DerpQuery>,
    State(state): State<Arc<DerpState>>,
) -> impl IntoResponse {
    // Require node secret for DERP connection
    let secret = match query.secret {
        Some(s) if s.starts_with("ns_") && s.len() == 35 => s,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                "Authentication required: provide valid node secret",
            )
                .into_response();
        }
    };

    // Verify node_secret against database
    if !state.verify_node_secret(&secret).await {
        tracing::warn!("DERP connection rejected: invalid node secret");
        return (StatusCode::UNAUTHORIZED, "Invalid node secret").into_response();
    }

    tracing::debug!("DERP connection authenticated with secret: {}...", &secret[..8]);

    ws.on_upgrade(move |socket| handle_connection(socket, state))
        .into_response()
}

async fn handle_connection(socket: WebSocket, state: Arc<DerpState>) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
    
    let mut client_key: Option<String> = None;
    
    // Task: Send messages to client
    let send_task = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if sender.send(Message::Binary(data.into())).await.is_err() {
                break;
            }
        }
    });
    
    // Receive messages from client
    while let Some(msg) = receiver.next().await {
        let data = match msg {
            Ok(Message::Binary(d)) => {
                // Check packet size limit to prevent memory exhaustion
                if d.len() > MAX_DERP_PACKET_SIZE {
                    tracing::warn!("DERP: Packet too large ({} bytes), dropping", d.len());
                    continue;
                }
                d.to_vec()
            }
            Ok(Message::Close(_)) => break,
            Err(_) => break,
            _ => continue,
        };

        if data.is_empty() {
            continue;
        }
        
        match data[0] {
            PKT_CLIENT_INFO => {
                if data.len() > 1 {
                    let key = String::from_utf8_lossy(&data[1..]).to_string();
                    // Check if registration succeeded (may fail if max clients reached)
                    if state.register(key.clone(), tx.clone()).await {
                        client_key = Some(key);
                    } else {
                        // Max clients reached, close connection
                        tracing::warn!("DERP: Closing connection - max clients limit reached");
                        break;
                    }
                }
            }
            PKT_SEND => {
                // Format: [type][key_len][key][payload]
                // Minimum: 1 (type) + 1 (key_len) + 1 (min key) = 3 bytes
                if data.len() >= 3 {
                    let key_len = data[1] as usize;
                    // Validate key_len is reasonable and data has enough bytes
                    if key_len > 0 && key_len <= 255 && data.len() >= 2 + key_len {
                        let dest_key = String::from_utf8_lossy(&data[2..2+key_len]).to_string();
                        let payload = data[2+key_len..].to_vec();

                        // Build receive packet
                        let mut recv_pkt = vec![PKT_RECV];
                        if let Some(ref from) = client_key {
                            // Ensure from key length fits in u8
                            let from_len = from.len().min(255);
                            recv_pkt.push(from_len as u8);
                            recv_pkt.extend(from.as_bytes().iter().take(from_len));
                        }
                        recv_pkt.extend(payload);

                        let _ = state.relay(&dest_key, recv_pkt).await;
                    }
                }
            }
            PKT_KEEPALIVE => {
                // Acknowledged by staying connected
            }
            _ => {}
        }
    }
    
    // Cleanup
    if let Some(key) = client_key {
        state.unregister(&key).await;
    }
    
    send_task.abort();
}
