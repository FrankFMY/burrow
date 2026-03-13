# Burrow

The fastest, most private, and easiest to use VPN & proxy for censorship circumvention.

**Deploy a server in one command. Share access with a link. Connect in one click.**

## What is Burrow?

Burrow is a self-hosted VPN/proxy system designed for people living under internet censorship. It combines military-grade traffic camouflage with dead-simple UX.

- **Undetectable** — VLESS+Reality makes your traffic look like normal HTTPS to any website. DPI cannot distinguish it from legitimate traffic.
- **Fast** — Direct VLESS+Reality tunnel with zero overhead.
- **Simple** — Server deploys with Docker. Users connect by pasting an invite link. Zero configuration.
- **Private** — Self-hosted. You control the server. No logs by default. No telemetry. No third parties.

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/FrankFMY/burrow.git
cd burrow
# Edit docker-compose.yml with your settings
docker compose up -d
```

### Manual

```bash
# Prerequisites: Go 1.26+, Node.js 22+
git clone https://github.com/FrankFMY/burrow.git
cd burrow
make all

# Initialize server
burrow-server init --password <your-password> --server <your-ip>
burrow-server run
```

### Create an invite

Open the admin dashboard at `https://your-server/admin`, log in, and create an invite from the Invites page. Or via CLI:

```bash
burrow-server invite create --name "My phone"
```

### Client

```bash
burrow connect "burrow://connect/..."
```

Or use the desktop client app — it guides you through setup with a built-in onboarding flow.

## Protocols

| Protocol | Port | Description |
|----------|------|-------------|
| VLESS+Reality | 443/TCP | Camouflaged as real HTTPS traffic, undetectable by DPI |
| VLESS+WebSocket (CDN) | 8080/TCP | Cloudflare-fronted, bypasses IP-based blocking |
| Hysteria2 | 8443/UDP | QUIC-based, optimized for lossy networks |
| Shadowsocks 2022 | 8388/TCP | Modern encryption (2022-blake3-aes-256-gcm) |
| WireGuard | 51820/UDP | Standard VPN protocol (disabled by default) |
| TCP Relay/Bridge | any/TCP | Forwards traffic to upstream server, hides real server IP |

VLESS+Reality is the primary protocol. If the direct connection is blocked, the client automatically falls back to CDN WebSocket transport. Hysteria2 and Shadowsocks 2022 are enabled by default as additional fallbacks. The client uses [sing-box](https://sing-box.sagernet.org/) as the tunnel engine with uTLS Chrome fingerprinting and Reality protocol for TLS camouflage.

## Features

### Server
- **One-command deploy** with Docker or manual setup
- **Admin dashboard** — manage clients, create invites, monitor traffic in real-time (auto-refresh)
- **Landing page** — public landing page at your server root
- **Invite-only access** — HMAC-signed invite links, revoke access instantly
- **CDN/Cloudflare fronting** — VLESS over WebSocket, Cloudflare terminates TLS
- **Relay/bridge mode** — `burrow-server relay` masks real server IP behind entry node
- **Secret rotation** — rotate Reality keys, ShortID, and JWT secret via API with legacy key tracking
- **Config validation** — actionable error messages on invalid config fields at startup
- **Security hardened** — request size limits, input validation, IP spoofing prevention, connection limits
- **Docker hardened** — non-root user, healthcheck, resource limits
- **DNS leak prevention** — all DNS through encrypted tunnel
- **CI/CD** — automated builds, tests, and deployment via GitHub Actions

### Desktop Client
- **One-click connect** — big connect button, no configuration needed
- **VPN mode (TUN)** — routes all system traffic through VPN, no proxy setup required
- **Proxy mode** — SOCKS5/HTTP on `127.0.0.1:1080` for manual configuration
- **Kill switch** — blocks ALL internet if VPN drops, prevents unprotected browsing
- **Auto-reconnect** — detects dead tunnel and reconnects with exponential backoff (up to 10 attempts), cancel anytime
- **Live speed stats** — real-time upload/download speed (KB/s, MB/s) with total traffic counters
- **Server ping** — latency measurement for each server, color-coded badges
- **Server switching** — switch servers while connected without manual disconnect
- **Desktop notifications** — system notifications on connect and disconnect
- **System tray** — dynamic menu reflects connection state, tooltip shows status
- **Auto-connect** — automatic connection on app launch with auto-reconnect on drops
- **Auto-update** — checks for new versions on startup, downloads and installs automatically
- **Single instance** — prevents duplicate app windows, focuses existing window
- **Window state** — remembers window size and position across sessions
- **Deep links** — `burrow://connect/...` URLs to add servers from browser
- **Onboarding** — first-run wizard guides new users through setup
- **Localization** — English, Russian, Chinese (auto-detected from system locale)
- **Persistent preferences** — settings saved with visual confirmation
- **Split tunneling** — bypass VPN for selected domains and IP ranges
- **Connection fallback** — auto-probes direct, falls back to CDN WebSocket if blocked
- **Cross-platform** — Linux, macOS, Windows (mobile iOS/Android scaffold ready)

## Architecture

```
Server (VPS)                              Client (your device)
┌──────────────────────────┐             ┌──────────────────────────┐
│ Landing Page             │             │ Desktop Client (Tauri 2) │
│ Admin Dashboard          │  direct     │   Onboarding wizard      │
│ Management API           │◄───────────►│   Connect / Disconnect   │
│ Transport Engine         │  encrypted  │   Split tunneling        │
│   VLESS+Reality (443)    │  tunnel     │ Tunnel Engine (sing-box) │
│   VLESS+WS/CDN (8080)   │             │   VPN (TUN) / Proxy mode │
│   Hysteria2 (8443)       │             │   Kill switch            │
│ SQLite DB                │             │   Fallback chain         │
└──────────────────────────┘             │ Client Daemon (HTTP API) │
         ▲                               │   :9090 local only       │
         │ relay                         └──────────────────────────┘
┌──────────────────────────┐                      │
│ Relay / Bridge Node      │◄─────────────────────┘
│   TCP forwarding         │  when direct blocked
└──────────────────────────┘
```

## API

### Server API

All endpoints require admin JWT except `/health` and `/api/connect`.

```
GET  /health                    Liveness check
POST /api/auth/login            Admin login → JWT
POST /api/auth/logout           Admin logout
POST /api/connect               Client config (token auth)
GET  /api/clients               List all clients
GET  /api/clients/:id           Get single client
DELETE /api/clients/:id         Revoke client
GET  /api/invites               List invites
POST /api/invites               Create invite
DELETE /api/invites/:id         Revoke invite
GET  /api/stats                 Server statistics
GET  /api/config                Server configuration
POST /api/rotate-keys           Rotate Reality keys, ShortID, JWT secret
```

### Client Daemon API

The desktop client runs a local daemon on `127.0.0.1:9090`.

```
GET  /api/status                Connection status, traffic stats, uptime
POST /api/connect               Start VPN tunnel
POST /api/disconnect            Stop VPN tunnel
GET  /api/servers               List configured servers
POST /api/servers               Add server from invite link
DELETE /api/servers/:name       Remove server
GET  /api/servers/:name/ping   Measure server latency (TCP connect time)
GET  /api/preferences           Get user preferences (VPN mode, kill switch, auto-connect)
PUT  /api/preferences           Update preferences
GET  /api/version               Daemon version and config directory
```

## Desktop Client

Native desktop applications are built with [Tauri 2](https://v2.tauri.app/) and available for Windows, macOS, and Linux.

Download the latest release from [GitHub Releases](https://github.com/FrankFMY/burrow/releases):

| Platform | File |
|----------|------|
| Windows (x64) | `Burrow_x.x.x_x64-setup.exe` or `.msi` |
| macOS (Apple Silicon) | `Burrow_x.x.x_aarch64.dmg` |
| macOS (Intel) | `Burrow_x.x.x_x64.dmg` |
| Linux (x64) | `Burrow_x.x.x_amd64.AppImage` or `.deb` |

### Usage

1. Install and open the app
2. The onboarding wizard guides you through setup
3. Paste your invite link (get one from admin dashboard)
4. Click **Add & Connect** — done

The app defaults to VPN mode, routing all system traffic through the tunnel. No proxy configuration needed.

### System Tray

The app minimizes to system tray on close. Right-click the tray icon for quick connect/disconnect.

## Building from Source

```bash
# Prerequisites: Go 1.26+, Node.js 22+
git clone https://github.com/FrankFMY/burrow.git
cd burrow

# Build admin dashboard
cd web/admin && npm install && npm run build && cd ../..

# Build Go binaries
make all

# Binaries: bin/burrow-server, bin/burrow
```

### Desktop Client (Tauri)

```bash
# Additional prerequisites: Rust 1.77+, platform-specific Tauri dependencies
# See https://v2.tauri.app/start/prerequisites/

cd web/client
npm install
npx tauri build

# Output: src-tauri/target/release/bundle/
```

## Deployment

### Docker Compose

```bash
docker compose build
docker compose up -d
```

### CI/CD

Push to `main` triggers automatic deployment via GitHub Actions. Configure these secrets:
- `DEPLOY_HOST` — server hostname/IP
- `DEPLOY_USER` — SSH username
- `DEPLOY_KEY` — SSH private key

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Author

**Pryanishnikov Artem**
- Email: Pryanishnikovartem@gmail.com
- Telegram: [@FrankFMY](https://t.me/FrankFMY)
- GitHub: [@FrankFMY](https://github.com/FrankFMY)
