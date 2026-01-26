<div align="center">

# Burrow

**Simple, fast, open-source mesh VPN**

[![CI](https://github.com/FrankFMY/burrow/actions/workflows/ci.yml/badge.svg)](https://github.com/FrankFMY/burrow/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

[Installation](#-installation) | [Quick Start](#-quick-start) | [Features](#-features) | [API](#-api) | [Contributing](#-contributing)

</div>

---

## Features

- **Fast** — Built on WireGuard protocol
- **Secure** — End-to-end encryption, modern cryptography, 2FA support
- **Mesh networking** — Direct peer-to-peer connections
- **NAT traversal** — STUN for hole punching, DERP relay fallback
- **Simple** — One command to join a network
- **Real-time** — WebSocket for live status updates
- **Web UI** — Beautiful dashboard for management
- **Docker ready** — Easy self-hosting
- **Open source** — Apache 2.0 licensed, free forever

## Security Features

| Feature | Description |
|---------|-------------|
| **2FA/TOTP** | Two-factor authentication with authenticator apps |
| **API Keys** | Secure CLI access with revocable API keys |
| **Audit Logging** | All security events are logged |
| **Rate Limiting** | Protection against brute-force attacks |
| **Ownership ACL** | Users can only access their own networks |
| **x25519 Keys** | Modern elliptic-curve cryptography |

## Installation

### One-line install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/FrankFMY/burrow/main/scripts/install.sh | bash
```

### From source

```bash
git clone https://github.com/FrankFMY/burrow.git
cd burrow
cargo build --release
```

### Docker

```bash
docker pull ghcr.io/frankfmy/burrow:latest
docker run -d -p 3000:3000 -v burrow-data:/data ghcr.io/frankfmy/burrow
```

## Quick Start

### 1. Start the server

```bash
burrow-server
# Server listening on 0.0.0.0:3000
```

### 2. Register and login

```bash
burrow register --email you@example.com --name "Your Name"
burrow login --email you@example.com
```

### 3. Create a network

```bash
burrow create-network "My Network"
# Network created!
#    ID: abc123...
```

### 4. Generate invite code

```bash
burrow invite <network-id>
# Invite code: ABCD1234
#    Share: burrow join ABCD1234
```

### 5. Join from any device

```bash
burrow join ABCD1234 --name "My Laptop"
# Successfully joined!
#    Mesh IP: 10.100.0.1
```

### 6. Connect

```bash
burrow up
# Agent started! Connected to network.
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `burrow register` | Register a new account |
| `burrow login` | Login to your account |
| `burrow logout` | Logout and clear credentials |
| `burrow create-network <name>` | Create a new network |
| `burrow invite <network-id>` | Generate invite code |
| `burrow join <code> [--name NAME]` | Join a network |
| `burrow up` | Start VPN connection |
| `burrow down` | Stop VPN connection |
| `burrow status` | Show connection status |
| `burrow peers` | List connected peers |

## Architecture

```
+-------------+     +-------------+     +-------------+
|   Node A    |---->|   Server    |<----|   Node B    |
|  (Agent)    |     |(Coordinator)|     |  (Agent)    |
+-------------+     +-------------+     +-------------+
       |                   |                   |
       |                   | DERP relay        |
       |                   | (fallback)        |
       +-------------------+-------------------+
                    WireGuard P2P
```

### Components

| Component | Description |
|-----------|-------------|
| `burrow-server` | Coordination server, DERP relay, WebSocket |
| `burrow` | CLI tool |
| `burrow-agent` | WireGuard manager daemon |
| `web/` | Admin dashboard (Svelte + Bun) |

## API

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/register` | POST | Register new user |
| `/api/auth/login` | POST | Login, get JWT token |
| `/api/auth/me` | GET | Get current user info |
| `/api/auth/totp` | GET | Get 2FA status |
| `/api/auth/totp/enable` | POST | Enable 2FA, get QR code |
| `/api/auth/totp/verify` | POST | Verify 2FA setup |
| `/api/auth/totp/disable` | POST | Disable 2FA |
| `/api/auth/api-keys` | GET/POST | List/Create API keys |
| `/api/auth/api-keys/:id` | DELETE | Revoke API key |

### Networks

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/networks` | GET | List user's networks |
| `/api/networks` | POST | Create new network |
| `/api/networks/:id` | GET | Get network details |
| `/api/networks/:id` | DELETE | Delete network |
| `/api/networks/:id/nodes` | GET | List nodes in network |
| `/api/networks/:id/invite` | POST | Generate invite code |

### Nodes

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/register` | POST | Register node with invite |
| `/api/nodes/:id/heartbeat` | POST | Node heartbeat |

### WebSocket

| Endpoint | Description |
|----------|-------------|
| `/ws?network_id=ID` | Real-time events stream |

Events: `NodeJoined`, `NodeStatus`, `NodeLeft`, `NetworkCreated`, `NetworkDeleted`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:burrow.db?mode=rwc` | Database connection |
| `JWT_SECRET` | random | JWT signing secret |
| `BIND_ADDR` | `0.0.0.0:3000` | Server bind address |
| `RUST_LOG` | `burrow_server=debug,info` | Log level |
| `CORS_ALLOW_ALL` | `false` | Allow all CORS origins |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Allowed CORS origins |

## Development

### Prerequisites

- Rust 1.70+
- Bun 1.0+
- WireGuard tools

### Build

```bash
# Rust components
cargo build --release

# Web UI
cd web && bun install && bun run build
```

### Run tests

```bash
cargo test --all
```

### Run development

```bash
# Terminal 1: Server
cargo run --bin burrow-server

# Terminal 2: Web UI
cd web && bun run dev
```

## Docker Compose

```yaml
version: '3.8'
services:
  burrow:
    image: ghcr.io/frankfmy/burrow:latest
    ports:
      - "3000:3000"
    environment:
      - JWT_SECRET=your-secret-here
      - DATABASE_URL=sqlite:/data/burrow.db?mode=rwc
    volumes:
      - burrow-data:/data
    restart: unless-stopped

volumes:
  burrow-data:
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Author

**Pryanishnikov Artem Alekseevich**

- Email: Pryanishnikovartem@gmail.com
- Telegram: [@FrankFMY](https://t.me/FrankFMY)
- GitHub: [@FrankFMY](https://github.com/FrankFMY)

## Contributing

Contributions welcome! Please read our contributing guidelines and submit a pull request.

---

<div align="center">

Made with love by [Artem Pryanishnikov](https://github.com/FrankFMY)

</div>
