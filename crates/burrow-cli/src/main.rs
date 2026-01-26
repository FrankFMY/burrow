//! Burrow CLI - Command line interface for Burrow VPN

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "burrow")]
#[command(about = "🕳️  Burrow - Simple, fast, open-source mesh VPN", long_about = None)]
#[command(version)]
struct Cli {
    /// Server URL
    #[arg(short, long, default_value = "http://localhost:3000")]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new account
    Register {
        /// Email address
        #[arg(short, long)]
        email: Option<String>,
        /// Your name
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Login to the server
    Login {
        /// Email address
        #[arg(short, long)]
        email: Option<String>,
    },
    /// Logout and clear credentials
    Logout,
    /// Join a network using an invite code
    Join {
        /// Invite code
        code: String,
        /// Node name
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Start the agent (connect to network)
    Up,
    /// Stop the agent
    Down,
    /// Show current status
    Status,
    /// List peers in the network
    Peers,
    /// Create a new network (requires auth)
    CreateNetwork {
        /// Network name
        name: String,
    },
    /// Generate an invite code (requires auth)
    Invite {
        /// Network ID
        network_id: String,
    },
    /// List your networks
    Networks,
}

/// Agent configuration
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
struct AgentConfig {
    server_url: String,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    node_id: Option<String>,
    #[serde(default)]
    network_id: Option<String>,
    #[serde(default)]
    node_secret: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    mesh_ip: Option<String>,
    #[serde(default)]
    network_cidr: Option<String>,
}

fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("burrow")
}

fn config_path() -> PathBuf {
    config_dir().join("agent.json")
}

fn load_config() -> AgentConfig {
    let path = config_path();
    if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|data| serde_json::from_str(&data).ok())
            .unwrap_or_default()
    } else {
        AgentConfig::default()
    }
}

fn save_config(config: &AgentConfig) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(config)?)?;
    Ok(())
}

fn authed_client(config: &AgentConfig) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(ref api_key) = config.api_key {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("ApiKey {}", api_key).parse().unwrap(),
        );
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = load_config();
    config.server_url = cli.server.clone();

    match cli.command {
        Commands::Register { email, name } => {
            let email = match email {
                Some(e) => e,
                None => {
                    print!("Email: ");
                    use std::io::Write;
                    std::io::stdout().flush()?;
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            let name = match name {
                Some(n) => n,
                None => {
                    print!("Name: ");
                    use std::io::Write;
                    std::io::stdout().flush()?;
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            print!("Password: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let password = rpassword::read_password()?;

            print!("Confirm password: ");
            std::io::stdout().flush()?;
            let password_confirm = rpassword::read_password()?;

            if password != password_confirm {
                println!("Passwords do not match");
                return Ok(());
            }

            if password.len() < 8 {
                println!("Password must be at least 8 characters");
                return Ok(());
            }

            println!("Registering...");

            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{}/api/auth/register", cli.server))
                .json(&serde_json::json!({
                    "email": email,
                    "password": password,
                    "name": name,
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;

                // Create API key for CLI
                let token = result["token"].as_str().unwrap_or("");
                let resp = client
                    .post(format!("{}/api/auth/api-keys", cli.server))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({
                        "name": format!("CLI on {}", hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_else(|_| "unknown".to_string())),
                    }))
                    .send()
                    .await?;

                if resp.status().is_success() {
                    let api_key_result: serde_json::Value = resp.json().await?;
                    config.api_key = Some(api_key_result["key"].as_str().unwrap_or("").to_string());
                    save_config(&config)?;

                    println!("Account created successfully!");
                    println!("   Email: {}", result["user"]["email"]);
                    println!("   Role: {}", result["user"]["role"]);
                }
            } else {
                let error: serde_json::Value = resp.json().await?;
                println!("Registration failed: {}", error["error"]);
            }
        }

        Commands::Login { email } => {
            let email = match email {
                Some(e) => e,
                None => {
                    print!("Email: ");
                    use std::io::Write;
                    std::io::stdout().flush()?;
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            print!("Password: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let password = rpassword::read_password()?;

            println!("🔐 Logging in...");

            let client = reqwest::Client::new();

            // First attempt without 2FA code
            let resp = client
                .post(format!("{}/api/auth/login", cli.server))
                .json(&serde_json::json!({
                    "email": email,
                    "password": password,
                }))
                .send()
                .await?;

            let (token, user_info) = if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;
                (result["token"].as_str().unwrap_or("").to_string(), result)
            } else {
                let error: serde_json::Value = resp.json().await?;
                let error_msg = error["error"].as_str().unwrap_or("");

                // Check if 2FA is required
                if error_msg.contains("2FA") || error_msg.contains("code required") {
                    print!("🔐 2FA Code: ");
                    std::io::stdout().flush()?;
                    let mut totp_code = String::new();
                    std::io::stdin().read_line(&mut totp_code)?;
                    let totp_code = totp_code.trim();

                    // Retry with 2FA code
                    let resp = client
                        .post(format!("{}/api/auth/login", cli.server))
                        .json(&serde_json::json!({
                            "email": email,
                            "password": password,
                            "totp_code": totp_code,
                        }))
                        .send()
                        .await?;

                    if resp.status().is_success() {
                        let result: serde_json::Value = resp.json().await?;
                        (result["token"].as_str().unwrap_or("").to_string(), result)
                    } else {
                        let error: serde_json::Value = resp.json().await?;
                        println!("❌ Login failed: {}", error["error"]);
                        return Ok(());
                    }
                } else {
                    println!("❌ Login failed: {}", error_msg);
                    return Ok(());
                }
            };

            // Check for existing API key for this hostname
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            let key_name = format!("CLI on {}", hostname);

            // Get existing API keys
            let resp = client
                .get(format!("{}/api/auth/api-keys", cli.server))
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await?;

            if resp.status().is_success() {
                let keys: Vec<serde_json::Value> = resp.json().await?;
                // Check if key for this hostname already exists
                for key in &keys {
                    if key["name"].as_str() == Some(&key_name) {
                        // Key exists but we don't have the actual key value (it's not returned in list)
                        // So we need to create a new one anyway, but inform the user
                        println!("ℹ️  Existing CLI key found for this device, creating new one...");
                        break;
                    }
                }
            }

            // Create new API key
            let resp = client
                .post(format!("{}/api/auth/api-keys", cli.server))
                .header("Authorization", format!("Bearer {}", token))
                .json(&serde_json::json!({ "name": key_name }))
                .send()
                .await?;

            if resp.status().is_success() {
                let api_key_result: serde_json::Value = resp.json().await?;
                config.api_key = Some(api_key_result["key"].as_str().unwrap_or("").to_string());
                save_config(&config)?;

                println!("✅ Logged in as {}", user_info["user"]["email"]);
                println!("   Role: {}", user_info["user"]["role"]);
            }
        }

        Commands::Logout => {
            config.api_key = None;
            save_config(&config)?;
            println!("✅ Logged out");
        }

        Commands::Join { code, name } => {
            let node_name = name.unwrap_or_else(|| {
                hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".to_string())
            });

            println!("🔗 Joining network with invite code: {}", code);

            // Generate keypair
            let keypair = burrow_core::crypto::KeyPair::generate();

            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{}/api/register", cli.server))
                .json(&serde_json::json!({
                    "invite_code": code,
                    "name": node_name,
                    "public_key": keypair.public_key,
                    "endpoint": Option::<String>::None,
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let result: serde_json::Value = resp.json().await?;

                // Update config
                config.node_id = Some(result["node"]["id"].as_str().unwrap_or("").to_string());
                config.network_id = Some(result["network_id"].as_str().unwrap_or("").to_string());
                config.node_secret = Some(result["node_secret"].as_str().unwrap_or("").to_string());
                config.private_key = Some(keypair.private_key);
                config.public_key = Some(keypair.public_key);
                config.mesh_ip = Some(result["mesh_ip"].as_str().unwrap_or("").to_string());
                config.network_cidr = Some(result["network_cidr"].as_str().unwrap_or("").to_string());
                save_config(&config)?;

                println!("Successfully joined network!");
                println!("   Node ID: {}", result["node"]["id"]);
                println!("   Network ID: {}", result["network_id"]);
                println!("   Mesh IP: {}", result["mesh_ip"]);
                println!("   Network: {}", result["network_cidr"]);
                println!("   Peers: {}", result["peers"].as_array().map(|p| p.len()).unwrap_or(0));
                println!();
                println!("   Run 'burrow up' to connect!");
            } else {
                let error: serde_json::Value = resp.json().await?;
                println!("❌ Failed to join: {}", error["error"]);
            }
        }

        Commands::Up => {
            println!("🚀 Starting Burrow agent...");

            if config.node_id.is_none() {
                println!("❌ Not configured. Run 'burrow join <code>' first.");
                return Ok(());
            }

            // Start agent process
            let status = std::process::Command::new("burrow-agent").spawn();

            match status {
                Ok(_) => println!("✅ Agent started!"),
                Err(e) => println!("❌ Failed to start agent: {}", e),
            }
        }

        Commands::Down => {
            println!("🛑 Stopping Burrow agent...");

            #[cfg(unix)]
            {
                let _ = std::process::Command::new("pkill")
                    .args(["-f", "burrow-agent"])
                    .status();
            }

            println!("✅ Agent stopped");
        }

        Commands::Status => {
            println!("📊 Burrow Status");
            println!("   Server: {}", config.server_url);

            if config.api_key.is_some() {
                println!("   Auth: 🟢 Logged in");
            } else {
                println!("   Auth: 🔴 Not logged in (run 'burrow login')");
            }

            if let Some(ref node_id) = config.node_id {
                println!("   Node ID: {}", node_id);
            }
            if let Some(ref mesh_ip) = config.mesh_ip {
                println!("   Mesh IP: {}", mesh_ip);
            }

            // Check if agent is running
            #[cfg(unix)]
            {
                let output = std::process::Command::new("pgrep")
                    .args(["-f", "burrow-agent"])
                    .output();

                if let Ok(out) = output {
                    if out.status.success() {
                        println!("   Agent: 🟢 Connected");
                    } else {
                        println!("   Agent: 🔴 Disconnected (run 'burrow up')");
                    }
                }
            }
        }

        Commands::Peers => {
            if config.node_id.is_none() {
                println!("❌ Not configured. Run 'burrow join <code>' first.");
                return Ok(());
            }

            // Get WireGuard status
            let output = std::process::Command::new("sudo")
                .args(["wg", "show", "burrow0"])
                .output();

            match output {
                Ok(out) => {
                    if out.status.success() {
                        println!("👥 Connected Peers:\n");
                        println!("{}", String::from_utf8_lossy(&out.stdout));
                    } else {
                        println!("👥 No peers connected (agent not running?)");
                    }
                }
                Err(_) => println!("👥 Could not get peer info"),
            }
        }

        Commands::Networks => {
            if config.api_key.is_none() {
                println!("❌ Not logged in. Run 'burrow login' first.");
                return Ok(());
            }

            let client = authed_client(&config);
            let resp = client
                .get(format!("{}/api/networks", cli.server))
                .send()
                .await?;

            if resp.status().is_success() {
                let networks: Vec<serde_json::Value> = resp.json().await?;
                println!("🌐 Your Networks:\n");
                if networks.is_empty() {
                    println!("   No networks yet. Create one with 'burrow create-network <name>'");
                } else {
                    for net in networks {
                        println!("   {} - {} ({})",
                            net["id"].as_str().unwrap_or("").chars().take(8).collect::<String>(),
                            net["name"],
                            net["cidr"]
                        );
                    }
                }
            } else {
                let error: serde_json::Value = resp.json().await?;
                println!("❌ Failed: {}", error["error"]);
            }
        }

        Commands::CreateNetwork { name } => {
            if config.api_key.is_none() {
                println!("❌ Not logged in. Run 'burrow login' first.");
                return Ok(());
            }

            println!("🌐 Creating network: {}", name);

            let client = authed_client(&config);
            let resp = client
                .post(format!("{}/api/networks", cli.server))
                .json(&serde_json::json!({ "name": name }))
                .send()
                .await?;

            if resp.status().is_success() {
                let network: serde_json::Value = resp.json().await?;
                println!("✅ Network created!");
                println!("   ID: {}", network["id"]);
                println!("   CIDR: {}", network["cidr"]);
                println!();
                println!("   Next: burrow invite {}", network["id"].as_str().unwrap_or(""));
            } else {
                let error: serde_json::Value = resp.json().await?;
                println!("❌ Failed: {}", error["error"]);
            }
        }

        Commands::Invite { network_id } => {
            if config.api_key.is_none() {
                println!("❌ Not logged in. Run 'burrow login' first.");
                return Ok(());
            }

            println!("🎟️  Generating invite code...");

            let client = authed_client(&config);
            let resp = client
                .post(format!("{}/api/networks/{}/invite", cli.server, network_id))
                .send()
                .await?;

            if resp.status().is_success() {
                let invite: serde_json::Value = resp.json().await?;
                println!("✅ Invite code: {}", invite["code"]);
                println!("   Expires: {}", invite["expires_at"]);
                println!();
                println!("   Share this command:");
                println!("   burrow join {}", invite["code"].as_str().unwrap_or(""));
            } else {
                let error: serde_json::Value = resp.json().await?;
                println!("❌ Failed: {}", error["error"]);
            }
        }
    }

    Ok(())
}
