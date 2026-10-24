# Burrow

A self-hosted VPN and proxy with invite-based access, desktop clients and multiple transports for restrictive networks.

**Run your own server. Share an invite. Connect from a desktop app or CLI.**

## What is Burrow?

Burrow is a self-hosted VPN/proxy system designed for people living under internet censorship. It combines VLESS+Reality and alternative transports with a straightforward admin dashboard and invite-based onboarding.

- **Transport options** — VLESS+Reality with uTLS Chrome fingerprinting, plus CDN WebSocket, Hysteria2 and Shadowsocks 2022 paths.
- **Direct when possible** — the client probes the direct path and can fall back to a configured CDN WebSocket route.
- **Invite-based setup** — administrators configure the server; users add an invite link instead of entering transport settings by hand.
- **Self-hosted control** — you choose the server, issue and revoke access, and inspect operational logs and traffic counters in the dashboard.

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/FrankFMY/burrow.git
cd burrow
# Review the initialization and port notes below before starting the service.
docker compose build
```

### Manual

```bash
# Prerequisites: Go 1.26.1+, Node.js 22+
git clone https://github.com/FrankFMY/burrow.git
cd burrow
npm --prefix web/admin ci
npm --prefix web/admin run build
make all

# Initialize a user-owned configuration on unprivileged ports.
CONFIG="$HOME/.config/burrow/burrow-server.json"
./bin/burrow-server init \
  --config "$CONFIG" --data-dir "$HOME/.local/share/burrow" \
  --port 8443 --api-port 9080 \
  --password '<your-admin-password>' --server vpn.example.com
./bin/burrow-server run --config "$CONFIG"
```

### Create an invite

After configuring HTTPS for the admin API, open `https://your-server/admin`, log in, and create an invite from the Invites page. The raw API listener defaults to port `8080` (`9080` in the manual example); the application does not provision that HTTPS endpoint for you. Or use the server CLI:

```bash
./bin/burrow-server invite create \
  --config "$HOME/.config/burrow/burrow-server.json" --name "My desktop"
```

### Client

```bash
./bin/burrow connect "burrow://connect/..."
```

Or use the desktop client app — it guides you through setup with a built-in onboarding flow.

## Protocols

| Protocol | Port | Description |
|----------|------|-------------|
| VLESS+Reality | 443/TCP | TLS camouflage using a configured target and uTLS fingerprinting |
| VLESS+WebSocket (CDN) | 8080/TCP | CDN-routed WebSocket transport when configured |
| Hysteria2 | 8443/UDP | QUIC-based, optimized for lossy networks |
| Shadowsocks 2022 | 8388/TCP | Modern encryption (2022-blake3-aes-256-gcm) |
| WireGuard | 51820/UDP | Standard VPN protocol (disabled by default) |
| TCP Relay/Bridge | any/TCP | A separate TCP entry point forwarding to an upstream server |

VLESS+Reality is the primary protocol. If the direct connection is blocked, the client automatically falls back to CDN WebSocket transport. Hysteria2 and Shadowsocks 2022 are enabled by default as additional fallbacks. The client uses [sing-box](https://sing-box.sagernet.org/) as the tunnel engine with uTLS Chrome fingerprinting and Reality protocol for TLS camouflage.

## Transport and trust model

Reality and uTLS are tools for reducing recognizable transport signatures, not a promise of invisibility. A network operator can still block an endpoint, restrict UDP or interfere with a camouflage target. Available transports and performance depend on the network and server configuration.

The server operator is part of the trust boundary. The server and any configured CDN can observe connection metadata; HTTPS and other application-level encryption still protect their own payloads. Burrow is a connectivity tool, not an anonymity network. Operational logs and traffic counters are features, not a zero-logging guarantee.

Keep the admin API behind HTTPS and appropriate access controls. Treat invite links and server configuration as credentials. Test TUN, DNS, split-tunnel and kill-switch behavior on each target OS before relying on a deployment.

## Features

### Server
- **Docker or manual deployment** with explicit server initialization
- **Admin dashboard** — manage clients, create invites, monitor traffic in real-time (auto-refresh)
- **Landing page** — public landing page at your server root
- **Invite-based access** — HMAC-signed invite links and administrative revocation
- **CDN/Cloudflare fronting** — VLESS over WebSocket, Cloudflare terminates TLS
- **Relay/bridge mode** — `burrow-server relay` masks real server IP behind entry node
- **Secret rotation** — rotate Reality keys, ShortID, and JWT secret via API with legacy key tracking
- **Config validation** — actionable error messages on invalid config fields at startup
- **Per-user bandwidth limits** — set quota per client, enforced at connect time
- **Health metrics** — detailed server health with uptime, memory, goroutines, DB size
- **In-app log viewer** — ring-buffer log collector exposed via API
- **API controls** — request-size limits, input validation, forwarded-IP handling and connection limits
- **Docker hardened** — non-root user, healthcheck, resource limits
- **Tunnel DNS routing** — DNS uses the tunnel configuration; verify resolver behavior for your chosen mode and split-tunnel rules
- **CI/CD** — automated builds, tests, and deployment via GitHub Actions

### Desktop Client
- **One-click connect** — big connect button, no configuration needed
- **VPN mode (TUN)** — routes all system traffic through VPN, no proxy setup required
- **Proxy mode** — SOCKS5/HTTP on `127.0.0.1:1080` for manual configuration
- **Kill switch** — optional platform firewall rules to restrict traffic outside the tunnel; requires the appropriate OS privileges
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
- **Connection diagnostics** — `burrow diagnose` tests DNS, TCP, TLS, CDN, latency
- **UX tooltips** — detailed explanations for all settings, helpful for non-technical users
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
GET  /api/logs                  Recent log entries (limit param, max 500)
GET  /api/health/detailed       Detailed health: uptime, memory, goroutines, DB size
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
# Prerequisites: Go 1.26.1+, Node.js 22+
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

The Compose service expects a configuration file at `config/burrow-server.json` and runs as UID/GID `1000`. Create a private `config/` directory writable by that container user, then initialize it before the first start:

```bash
docker compose build
docker compose run --rm burrow init \
  --config /etc/burrow/burrow-server.json \
  --data-dir /var/lib/burrow \
  --password '<your-admin-password>' \
  --server vpn.example.com
docker compose up -d
```

Use your actual public server address and a unique admin password. Protect shell history and configuration files. The provided Compose mapping exposes TCP ports; publish `8443/udp` explicitly if using Hysteria2, and configure CDN listeners on a port distinct from the admin API. Server initialization configures transports; it does not configure your firewall, DNS, CDN or reverse proxy.

### CI/CD

A push to `main` triggers automatic deployment unless every changed path is one of `README.md`, `.github/workflows/ci.yml` or `.github/workflows/deploy.yml`. These three documentation/automation files are not application build inputs. Any other changed path, including runtime configuration or another workflow, retains automatic deployment; mixed changes do too. Normal verification CI still runs on pushes and pull requests. Manual deployment remains available through `workflow_dispatch` on `main`.

Configure these secrets:
- `DEPLOY_HOST` — server hostname/IP
- `DEPLOY_USER` — SSH username
- `DEPLOY_KEY` — SSH private key

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Author and contact

**Artem Prianishnikov** · [FrankFMY](https://github.com/FrankFMY)

[Website](https://frankfmy.com) · [Telegram](https://t.me/FrankFMY) · [LinkedIn](https://www.linkedin.com/in/frankfmy/) · [X](https://x.com/FrankFMY) · [npm profile](https://www.npmjs.com/~frankfmy)

Email: [frankfmy@proton.me](mailto:frankfmy@proton.me) · [Pryanishnikovartem@gmail.com](mailto:Pryanishnikovartem@gmail.com)
