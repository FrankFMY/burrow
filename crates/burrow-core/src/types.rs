//! Core types for Burrow VPN

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents a node in the Burrow mesh network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Unique identifier for the node
    pub id: Uuid,
    /// Human-readable name
    pub name: String,
    /// WireGuard public key
    pub public_key: String,
    /// Assigned IP address in the mesh network
    pub mesh_ip: String,
    /// Public endpoint (IP:port) if directly reachable
    pub endpoint: Option<String>,
    /// Node status
    pub status: NodeStatus,
    /// When the node was registered
    pub created_at: DateTime<Utc>,
    /// Last time the node was seen online
    pub last_seen: Option<DateTime<Utc>>,
}

/// Status of a node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Online,
    Offline,
    Pending,
}

/// A network (group of nodes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    /// Unique identifier
    pub id: Uuid,
    /// Network name
    pub name: String,
    /// CIDR for the mesh network (e.g., "10.100.0.0/16")
    pub cidr: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Invite code for joining a network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// The invite code
    pub code: String,
    /// Network to join
    pub network_id: Uuid,
    /// Expiration time
    pub expires_at: DateTime<Utc>,
    /// Maximum number of uses (None = unlimited)
    pub max_uses: Option<u32>,
    /// Current number of uses
    pub uses: u32,
}

/// Request to register a new node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterNodeRequest {
    /// Invite code
    pub invite_code: String,
    /// Node name
    pub name: String,
    /// WireGuard public key
    pub public_key: String,
    /// Public endpoint if available
    pub endpoint: Option<String>,
}

/// Response after registering a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterNodeResponse {
    /// The registered node
    pub node: Node,
    /// Network ID the node joined
    pub network_id: String,
    /// Assigned mesh IP
    pub mesh_ip: String,
    /// Network CIDR
    pub network_cidr: String,
    /// Other nodes in the network (peers)
    pub peers: Vec<Node>,
    /// Secret for authenticating heartbeat requests
    pub node_secret: String,
}
