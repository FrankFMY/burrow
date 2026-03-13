# Burrow

The fastest, most private, and easiest to use VPN & proxy for censorship circumvention.

**Deploy a server in one command. Share access with a link. Connect in one click.**

## What is Burrow?

Burrow is a self-hosted VPN/proxy system designed for people living under internet censorship. It combines military-grade traffic camouflage with dead-simple UX.

- **Undetectable** — VLESS+Reality makes your traffic look like normal HTTPS to any website. DPI cannot distinguish it from legitimate traffic.
- **Fast** — WireGuard for non-censored networks, Hysteria 2 (QUIC) for lossy mobile connections, automatic protocol selection.
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
# Prerequisites: Go 1.22+, Node.js 22+
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

Or use the desktop client app — paste the invite link in the Servers page and click Connect.

## Protocols

| Protocol | Port | Use Case |
|----------|------|----------|
| VLESS+Reality | 443/TCP | Primary — camouflaged as real HTTPS, undetectable by DPI |
| Hysteria 2 | 8443/UDP | Mobile/lossy networks — QUIC-based, fast handshake |
| Shadowsocks 2022 | 8388/TCP | Proven fallback — AEAD encryption |
| WireGuard | 51820/UDP | Maximum speed — for non-censored environments |

The client automatically selects the best working protocol. If one is blocked, it falls back to the next.

## Features

- **One-command server deploy** with Docker or manual setup
- **Admin dashboard** — manage clients, create invites, monitor traffic in real-time
- **Landing page** — beautiful landing page at your server root
- **Invite-only access** — generate secure links, revoke access instantly
- **Auto protocol selection** with intelligent fallback
- **Kill switch** — blocks all traffic if VPN disconnects (Linux, macOS, Windows)
- **DNS leak prevention** — all DNS through encrypted tunnel
- **Desktop client** — native app with one-click connect
- **Cross-platform** — Linux, macOS, Windows
- **CI/CD** — automated builds, tests, and deployment via GitHub Actions

## Architecture

```
Server (VPS)                          Client (your device)
┌─────────────────────┐              ┌─────────────────────┐
│ Landing Page        │              │ Desktop Client (UI) │
│ Admin Dashboard     │              │   Connect button    │
│ Management API      │              │   Server manager    │
│ Transport Engine    │◄────────────►│ Tunnel Engine       │
│   VLESS+Reality     │  encrypted   │   SOCKS5/HTTP proxy │
│   Hysteria 2        │  tunnel      │   Protocol auto-sel │
│   Shadowsocks 2022  │              │   Kill switch       │
│ SQLite DB           │              │ Client config       │
└─────────────────────┘              └─────────────────────┘
```

## API

All endpoints require admin JWT except `/health` and `/api/connect`.

```
GET  /health                    Liveness check
POST /api/auth/login            Admin login → JWT
POST /api/connect               Client config (token auth)
GET  /api/clients               List all clients
GET  /api/clients/:id           Get single client
DELETE /api/clients/:id         Revoke client
GET  /api/invites               List invites
POST /api/invites               Create invite
DELETE /api/invites/:id         Revoke invite
GET  /api/stats                 Server statistics
GET  /api/config                Server configuration
```

## Building from Source

```bash
# Prerequisites: Go 1.22+, Node.js 22+
git clone https://github.com/FrankFMY/burrow.git
cd burrow

# Build admin dashboard
cd web/admin && npm install && npm run build && cd ../..

# Build Go binaries
make all

# Binaries: bin/burrow-server, bin/burrow
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
