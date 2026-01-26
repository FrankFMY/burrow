//! WireGuard interface management

use anyhow::{Context, Result};
use std::process::Command;
use burrow_core::Node;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::io::Write;

/// WireGuard configuration for a node
pub struct WgConfig {
    pub interface_name: String,
    pub private_key: String,
    pub address: String,
    pub listen_port: u16,
}

impl WgConfig {
    pub fn new(private_key: String, address: String) -> Self {
        Self {
            interface_name: "burrow0".to_string(),
            private_key,
            address,
            listen_port: 51820,
        }
    }
}

/// Manages WireGuard interface
pub struct WireGuard {
    config: WgConfig,
}

impl WireGuard {
    pub fn new(config: WgConfig) -> Self {
        Self { config }
    }
    
    /// Check if WireGuard tools are installed
    pub fn check_installation() -> Result<()> {
        let output = Command::new("which")
            .arg("wg")
            .output()
            .context("Failed to check for wg command")?;
        
        if !output.status.success() {
            anyhow::bail!("WireGuard tools not installed. Run: sudo apt install wireguard-tools");
        }
        
        Ok(())
    }
    
    /// Create and configure the WireGuard interface
    pub fn setup_interface(&self) -> Result<()> {
        let iface = &self.config.interface_name;
        
        // Check if interface exists, if so bring it down first
        let _ = Command::new("sudo")
            .args(["ip", "link", "delete", iface])
            .output();
        
        // Create interface
        tracing::info!("Creating WireGuard interface: {}", iface);
        
        let status = Command::new("sudo")
            .args(["ip", "link", "add", iface, "type", "wireguard"])
            .status()
            .context("Failed to create WireGuard interface")?;
        
        if !status.success() {
            anyhow::bail!("Failed to create WireGuard interface");
        }
        
        // Set private key via temp file (wg requires file input)
        // Use secure permissions (0600) and UUID to prevent race conditions/prediction
        let key_file = format!("/tmp/burrow_wg_key_{}", uuid::Uuid::new_v4());

        #[cfg(unix)]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_file)
                .context("Failed to create secure key file")?;
            file.write_all(self.config.private_key.as_bytes())?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(&key_file, &self.config.private_key)?;
        }

        let wg_result = Command::new("sudo")
            .args(["wg", "set", iface, "private-key", &key_file, "listen-port",
                   &self.config.listen_port.to_string()])
            .status();

        // Always remove temp key file, even on error
        let _ = std::fs::remove_file(&key_file);

        let status = wg_result.context("Failed to set WireGuard private key")?;

        if !status.success() {
            anyhow::bail!("Failed to configure WireGuard interface");
        }
        
        // Assign IP address
        let addr_cidr = format!("{}/24", self.config.address);
        let status = Command::new("sudo")
            .args(["ip", "addr", "add", &addr_cidr, "dev", iface])
            .status()
            .context("Failed to assign IP address")?;
        
        if !status.success() {
            anyhow::bail!("Failed to assign IP address to interface");
        }
        
        // Bring interface up
        let status = Command::new("sudo")
            .args(["ip", "link", "set", iface, "up"])
            .status()
            .context("Failed to bring interface up")?;
        
        if !status.success() {
            anyhow::bail!("Failed to bring WireGuard interface up");
        }
        
        tracing::info!("✓ WireGuard interface {} configured with IP {}", iface, self.config.address);
        
        Ok(())
    }
    
    /// Add a peer to the WireGuard interface
    pub fn add_peer(&self, peer: &Node) -> Result<()> {
        let iface = &self.config.interface_name;

        tracing::info!("Adding peer: {} ({})", peer.name, peer.mesh_ip);

        // Pre-allocate strings to avoid temporary borrowing issues
        let allowed_ips = format!("{}/32", peer.mesh_ip);
        let endpoint_str = peer.endpoint.clone().unwrap_or_default();

        let mut args = vec![
            "wg", "set", iface,
            "peer", &peer.public_key,
            "allowed-ips", &allowed_ips,
        ];

        // Add endpoint if available
        if peer.endpoint.is_some() {
            args.push("endpoint");
            args.push(&endpoint_str);
        }

        // Add persistent keepalive for NAT traversal
        args.push("persistent-keepalive");
        args.push("25");
        
        let status = Command::new("sudo")
            .args(&args)
            .status()
            .context("Failed to add WireGuard peer")?;
        
        if !status.success() {
            anyhow::bail!("Failed to add peer {}", peer.name);
        }
        
        tracing::info!("✓ Added peer: {}", peer.name);
        
        Ok(())
    }
    
    /// Remove a peer from the WireGuard interface
    #[allow(dead_code)]
    pub fn remove_peer(&self, public_key: &str) -> Result<()> {
        let iface = &self.config.interface_name;
        
        let status = Command::new("sudo")
            .args(["wg", "set", iface, "peer", public_key, "remove"])
            .status()
            .context("Failed to remove peer")?;
        
        if !status.success() {
            anyhow::bail!("Failed to remove peer");
        }
        
        Ok(())
    }
    
    /// Get current interface status
    #[allow(dead_code)]
    pub fn status(&self) -> Result<String> {
        let output = Command::new("sudo")
            .args(["wg", "show", &self.config.interface_name])
            .output()
            .context("Failed to get WireGuard status")?;
        
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
    
    /// Cleanup - remove the interface
    pub fn cleanup(&self) -> Result<()> {
        let iface = &self.config.interface_name;
        
        tracing::info!("Removing WireGuard interface: {}", iface);
        
        let _ = Command::new("sudo")
            .args(["ip", "link", "delete", iface])
            .status();
        
        Ok(())
    }
}

impl Drop for WireGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
