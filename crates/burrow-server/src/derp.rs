//! DERP (Designated Encrypted Relay for Packets) server
//! 
//! Provides relay service when direct P2P connections fail.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Connected DERP client
struct DerpClient {
    public_key: String,
    tx: mpsc::Sender<Vec<u8>>,
}

/// DERP relay state
pub struct DerpState {
    clients: RwLock<HashMap<String, DerpClient>>,
}

impl DerpState {
    pub fn new() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
        }
    }
    
    async fn register(&self, public_key: String, tx: mpsc::Sender<Vec<u8>>) {
        let mut clients = self.clients.write().await;
        tracing::info!("DERP: Client registered: {}", &public_key[..8.min(public_key.len())]);
        clients.insert(public_key.clone(), DerpClient { public_key, tx });
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
    
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }
}

/// DERP packet types
const PKT_CLIENT_INFO: u8 = 0x01;
const PKT_SEND: u8 = 0x02;
const PKT_RECV: u8 = 0x03;
const PKT_KEEPALIVE: u8 = 0x04;

/// Handle WebSocket upgrade for DERP connection
pub async fn derp_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<DerpState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_connection(socket, state))
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
            Ok(Message::Binary(d)) => d.to_vec(),
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
                    client_key = Some(key.clone());
                    state.register(key, tx.clone()).await;
                }
            }
            PKT_SEND => {
                // Format: [type][key_len][key][payload]
                if data.len() > 2 {
                    let key_len = data[1] as usize;
                    if data.len() > 2 + key_len {
                        let dest_key = String::from_utf8_lossy(&data[2..2+key_len]).to_string();
                        let payload = data[2+key_len..].to_vec();
                        
                        // Build receive packet
                        let mut recv_pkt = vec![PKT_RECV];
                        if let Some(ref from) = client_key {
                            recv_pkt.push(from.len() as u8);
                            recv_pkt.extend(from.as_bytes());
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
