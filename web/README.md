# 🕳️ Burrow

**Simple, fast, open-source mesh VPN**

Burrow is a self-hosted mesh VPN solution that makes it easy to connect your devices securely. Built with Rust and modern web technologies.

## Features

- 🚀 **Fast** — Built on WireGuard protocol
- 🔒 **Secure** — End-to-end encryption
- 🌐 **Mesh networking** — Direct peer-to-peer connections
- 🎯 **Simple** — One command to join a network
- 🆓 **Open source** — MIT licensed, free forever

## Quick Start

### 1. Start the coordination server

```bash
./burrow-server
```

### 2. Create a network

```bash
./burrow create-network "My Network"
```

### 3. Generate an invite code

```bash
./burrow invite <network-id>
```

### 4. Join from any device

```bash
./burrow join <invite-code>
```

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Node A    │────▶│   Server    │◀────│   Node B    │
│  (Agent)    │     │(Coordinator)│     │  (Agent)    │
└─────────────┘     └─────────────┘     └─────────────┘
       │                                       │
       └───────────── WireGuard ──────────────┘
                   (Direct P2P)
```

## Components

- **burrow-server** — Coordination server (key exchange, node discovery)
- **burrow-agent** — Runs on each node, manages WireGuard
- **burrow** — CLI tool
- **web** — Admin dashboard (Svelte)

## Development

### Prerequisites

- Rust 1.70+
- Bun 1.3+
- WireGuard tools

### Build

```bash
# Build Rust components
cargo build --release

# Build web UI
cd web && bun install && bun run build
```

### Run development

```bash
# Terminal 1: Start server
cargo run --bin burrow-server

# Terminal 2: Start web UI
cd web && bun run dev
```

## License

MIT License — Use it, modify it, share it!

---

Made with ❤️ by the Burrow community
