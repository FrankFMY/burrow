//! STUN client for NAT traversal
//! 
//! Discovers public IP and port mapping for NAT hole punching

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// STUN message types
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute types
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN magic cookie (RFC 5389)
const MAGIC_COOKIE: u32 = 0x2112A442;

/// Public STUN servers
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// Result of STUN binding request
#[derive(Debug, Clone)]
pub struct StunResult {
    /// Our public IP address
    pub public_addr: SocketAddr,
    /// Local address used
    pub local_addr: SocketAddr,
    /// NAT type detected
    pub nat_type: NatType,
}

/// Detected NAT type
#[derive(Debug, Clone, PartialEq)]
pub enum NatType {
    /// No NAT (public IP)
    None,
    /// Full cone NAT (easiest for P2P)
    FullCone,
    /// Restricted cone NAT
    RestrictedCone,
    /// Port restricted cone NAT
    PortRestricted,
    /// Symmetric NAT (hardest for P2P)
    Symmetric,
    /// Unknown
    Unknown,
}

/// Perform STUN binding request to discover public address
pub fn discover_public_address() -> Result<StunResult, String> {
    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("Failed to bind socket: {}", e))?;
    
    socket.set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;
    
    let local_addr = socket.local_addr()
        .map_err(|e| format!("Failed to get local addr: {}", e))?;
    
    // Try each STUN server
    for server in STUN_SERVERS {
        if let Ok(result) = stun_request(&socket, server, local_addr) {
            return Ok(result);
        }
    }
    
    Err("All STUN servers failed".to_string())
}

fn stun_request(socket: &UdpSocket, server: &str, local_addr: SocketAddr) -> Result<StunResult, String> {
    // Build STUN binding request
    let transaction_id: [u8; 12] = rand::random();
    let mut request = Vec::with_capacity(20);
    
    // Message type: Binding Request
    request.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message length: 0 (no attributes)
    request.extend_from_slice(&0u16.to_be_bytes());
    // Magic cookie
    request.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    // Transaction ID
    request.extend_from_slice(&transaction_id);
    
    // Send request
    socket.send_to(&request, server)
        .map_err(|e| format!("Failed to send: {}", e))?;
    
    // Receive response
    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf)
        .map_err(|e| format!("Failed to receive: {}", e))?;
    
    // Parse response
    if len < 20 {
        return Err("Response too short".to_string());
    }
    
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err("Not a binding response".to_string());
    }
    
    // Parse XOR-MAPPED-ADDRESS attribute
    let public_addr = parse_xor_mapped_address(&buf[20..len], &transaction_id)?;
    
    Ok(StunResult {
        public_addr,
        local_addr,
        nat_type: NatType::Unknown, // Would need more tests to determine
    })
}

fn parse_xor_mapped_address(data: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr, String> {
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + attr_len > data.len() {
            break;
        }

        if attr_type == XOR_MAPPED_ADDRESS {
            let family = data[pos + 1];
            let xor_port = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let port = xor_port ^ (MAGIC_COOKIE >> 16) as u16;

            if family == 0x01 && attr_len >= 8 {
                // IPv4: XOR with magic cookie only
                let xor_ip =
                    u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
                let ip = xor_ip ^ MAGIC_COOKIE;
                let ip_bytes = ip.to_be_bytes();
                let addr =
                    std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                return Ok(SocketAddr::new(addr.into(), port));
            } else if family == 0x02 && attr_len >= 20 {
                // IPv6: XOR with magic cookie + transaction ID (RFC 5389)
                let mut xor_key = [0u8; 16];
                xor_key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                xor_key[4..16].copy_from_slice(transaction_id);

                let mut ip_bytes = [0u8; 16];
                for i in 0..16 {
                    ip_bytes[i] = data[pos + 4 + i] ^ xor_key[i];
                }
                let addr = std::net::Ipv6Addr::from(ip_bytes);
                return Ok(SocketAddr::new(addr.into(), port));
            }
        } else if attr_type == MAPPED_ADDRESS {
            // Fallback to non-XOR mapped address
            let family = data[pos + 1];
            let port = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);

            if family == 0x01 && attr_len >= 8 {
                let addr = std::net::Ipv4Addr::new(
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                );
                return Ok(SocketAddr::new(addr.into(), port));
            } else if family == 0x02 && attr_len >= 20 {
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[pos + 4..pos + 20]);
                let addr = std::net::Ipv6Addr::from(ip_bytes);
                return Ok(SocketAddr::new(addr.into(), port));
            }
        }

        pos += attr_len;
        // Align to 4 bytes
        pos = (pos + 3) & !3;
    }

    Err("No mapped address found".to_string())
}

/// Attempt NAT hole punching between two peers
pub fn punch_hole(local_socket: &UdpSocket, peer_addr: SocketAddr) -> Result<(), String> {
    // Send a few packets to punch through NAT
    let punch_data = b"BURROW_PUNCH";
    
    for _ in 0..3 {
        local_socket.send_to(punch_data, peer_addr)
            .map_err(|e| format!("Punch failed: {}", e))?;
        std::thread::sleep(Duration::from_millis(100));
    }
    
    Ok(())
}
