//! Burrow Agent - Runs on each node to manage WireGuard connections

use anyhow::{Context, Result};
use burrow_core::{crypto::KeyPair, Node, RegisterNodeRequest, RegisterNodeResponse};
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod wireguard;
use wireguard::{WgConfig, WireGuard};

/// Agent configuration stored locally
#[derive(serde::Serialize, serde::Deserialize)]
struct AgentConfig {
    server_url: String,
    node_id: String,
    network_id: String,
    #[serde(default)]
    node_secret: Option<String>,
    private_key: String,
    public_key: String,
    mesh_ip: String,
}

impl AgentConfig {
    fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("burrow")
            .join("agent.json")
    }
    
    async fn load() -> Result<Option<Self>> {
        let path = Self::config_path();
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(&path).await?;
        let config: Self = serde_json::from_str(&data)?;
        Ok(Some(config))
    }
    
    async fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let data = serde_json::to_string_pretty(self)?;
        fs::write(&path, data).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "burrow_agent=debug,info".into()),
        ))
        .init();

    tracing::info!("🕳️  Burrow Agent starting...");
    
    // Check WireGuard installation
    WireGuard::check_installation()?;
    tracing::info!("✓ WireGuard tools found");
    
    // Load or create config
    let config = match AgentConfig::load().await? {
        Some(config) => {
            tracing::info!("Loaded existing configuration");
            config
        }
        None => {
            tracing::info!("No configuration found. Use 'burrow join <code>' to join a network.");
            return Ok(());
        }
    };
    
    // Create HTTP client
    let client = reqwest::Client::new();
    
    // Setup WireGuard interface
    let wg_config = WgConfig::new(config.private_key.clone(), config.mesh_ip.clone());
    let wg = WireGuard::new(wg_config);
    
    wg.setup_interface()?;
    
    tracing::info!("🚀 Agent running. Press Ctrl+C to stop.");
    
    // Main loop - heartbeat and peer updates
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                match heartbeat(&client, &config, &wg).await {
                    Ok(_) => tracing::debug!("Heartbeat sent"),
                    Err(e) => tracing::warn!("Heartbeat failed: {}", e),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutting down...");
                break;
            }
        }
    }
    
    Ok(())
}

async fn heartbeat(
    client: &reqwest::Client,
    config: &AgentConfig,
    wg: &WireGuard,
) -> Result<()> {
    let url = format!("{}/api/nodes/{}/heartbeat", config.server_url, config.node_id);

    let node_secret = config.node_secret.clone().unwrap_or_default();

    let response = client
        .post(&url)
        .json(&serde_json::json!({ "node_secret": node_secret }))
        .send()
        .await
        .context("Failed to send heartbeat")?;

    if response.status().is_success() {
        let peers: Vec<Node> = response.json().await?;

        // Update peers in WireGuard
        for peer in &peers {
            if let Err(e) = wg.add_peer(peer) {
                tracing::warn!("Failed to add peer {}: {}", peer.name, e);
            }
        }

        tracing::debug!("Updated {} peers", peers.len());
    } else {
        tracing::warn!("Heartbeat failed: {}", response.status());
    }

    Ok(())
}

/// Join a network (called from CLI, saves config for agent)
pub async fn join_network(
    server_url: &str,
    invite_code: &str,
    node_name: &str,
) -> Result<RegisterNodeResponse> {
    let client = reqwest::Client::new();
    
    // Generate keypair
    let keypair = KeyPair::generate();
    
    // Get public endpoint (if available)
    let endpoint = get_public_endpoint().await;
    
    let request = RegisterNodeRequest {
        invite_code: invite_code.to_string(),
        name: node_name.to_string(),
        public_key: keypair.public_key.clone(),
        endpoint,
    };
    
    let response = client
        .post(format!("{}/api/register", server_url))
        .json(&request)
        .send()
        .await
        .context("Failed to register with server")?;
    
    if !response.status().is_success() {
        let error: serde_json::Value = response.json().await?;
        anyhow::bail!("Registration failed: {}", error["error"]);
    }
    
    let result: RegisterNodeResponse = response.json().await?;
    
    // Save config for agent
    let config = AgentConfig {
        server_url: server_url.to_string(),
        node_id: result.node.id.to_string(),
        network_id: result.network_id.clone(),
        node_secret: Some(result.node_secret.clone()),
        private_key: keypair.private_key,
        public_key: keypair.public_key,
        mesh_ip: result.mesh_ip.clone(),
    };
    
    config.save().await?;
    tracing::info!("Configuration saved to {:?}", AgentConfig::config_path());
    
    Ok(result)
}

async fn get_public_endpoint() -> Option<String> {
    // Try to get public IP
    let client = reqwest::Client::new();
    
    if let Ok(response) = client.get("https://api.ipify.org").send().await {
        if let Ok(ip) = response.text().await {
            return Some(format!("{}:51820", ip.trim()));
        }
    }
    
    None
}
