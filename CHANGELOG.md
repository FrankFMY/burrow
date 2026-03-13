# Changelog

## [0.5.2] - 2026-03-14

### Added
- **Prometheus metrics** — `/metrics` endpoint with 8 metrics: client counts, connections, bytes transferred, uptime, goroutines, memory, HTTP request duration histogram. Auto-updates every 15s.
- **Connection tracker** — real-time per-client traffic accounting. Clients report traffic via `POST /api/heartbeat` (periodic delta) and `POST /api/disconnect` (final bytes). Stale sessions auto-cleaned after 1 hour.
- **One-command deployment** — `scripts/deploy.sh` takes a fresh Ubuntu/Debian VPS to running Burrow server (binary install, firewall, systemd, auto-IP detection). Docker variant: `scripts/deploy-docker.sh`.
- **DPI resistance testing** — `scripts/dpi-test.sh` verifies TLS camouflage, active probing resistance, protocol detection, DNS leaks. Go integration tests with `dpi` build tag.
- **Threat model** — `docs/threat-model.md` documenting adversary capabilities, protocol security properties, and known limitations.

### Fixed
- SQLite `datetime('now')` → RFC3339 format (`strftime('%Y-%m-%dT%H:%M:%SZ')`) for correct time parsing in `RecordTraffic` and `CloseConnection`

## [0.5.1] - 2026-03-14

### Security
- JWT tokens stored in HttpOnly cookies instead of localStorage (XSS-proof)
- Logout now invalidates JWT server-side via token blocklist
- Client daemon requires auth token (`X-Burrow-Token` header) on all requests
- Content-Type enforcement on daemon API prevents CSRF attacks
- Kill switch validates `serverIP` is a valid IP before passing to firewall rules
- Rate limiter now keys on IP address only (stripped port), preventing per-connection bypass
- Auth.UpdateSecret protected with RWMutex (fixes data race during key rotation)
- Server config saves atomically via tmp+rename (prevents corruption on crash)
- Removed raw Go error details from daemon API responses
- Install script verifies SHA256 checksum before extracting binary
- Tauri updater signing keypair configured for secure auto-updates

### Fixed
- `/api/logs` endpoint now works (logBuffer was never initialized in production)
- Negative `limit` parameter in `/api/logs` now clamped to default
- Negative `bandwidth_limit` in invite creation now rejected with 400
- `LegacyPublicKeys` array capped at 5 entries (was growing unboundedly)
- macOS kill switch (`pfctl`) now returns error on failure instead of silently continuing
- `checkAndReconnect` no longer blocks daemon API for 2s while holding mutex
- Protocol in `/api/status` now reflects actual transport mode instead of hardcoded "vless-reality"
- Removed version from unauthenticated `/health` endpoint
- Admin invites page variable renamed from `clients` to `invites`
- Dashboard animation stagger class duplication fixed
- Added missing `<title>` tag in admin HTML
- Per-client bandwidth tracking via RecordTraffic (bytes_up/bytes_down now actually updated)

### Added
- API port included in invite data (clients no longer hardcode port 8080)
- Key rotation response includes `restart_required` flag and explanation
- Integration test covering full API flow (login → invite → connect → revoke)
- Tests for all previously untested API endpoints and store methods
- Tauri command `get_daemon_token` for secure daemon communication

### Changed
- Google Fonts replaced with system font stack (no external network requests)
- Admin auth middleware supports both cookie and Authorization header

## [0.5.0] - 2026-03-13

### Added
- **Connection diagnostics** — `burrow diagnose` command tests DNS, TCP, TLS, CDN reachability and latency
- **Server health metrics** — `GET /api/health/detailed` with uptime, memory, goroutines, DB size
- **Per-user bandwidth limits** — set bandwidth quota per client, 403 at connect when exceeded
- **In-app log viewer** — ring-buffer log collector with `GET /api/logs` endpoint (slog integration)
- **Config validation** — actionable error messages on invalid or missing config fields at startup
- **Secret rotation API** — `POST /api/rotate-keys` regenerates Reality keys, ShortID, and JWT secret with legacy key tracking
- **UX tooltips** — detailed explanations for all settings, helpful for non-technical users
- **Edge-case tests** — comprehensive tests for boundary conditions, nil configs, empty lists, and fuzz-like scenarios
- **Docker hardening** — non-root user, healthcheck, resource limits, .dockerignore

### Security
- Remove X-Forwarded-For trust (middleware.RealIP) — prevents IP spoofing for rate limiter bypass
- Add request body size limits (64KB) on all POST endpoints — prevents memory exhaustion
- Add input length validation: password (128 chars), client name (200 chars)
- Require HMAC signature on invite verification — reject unsigned invites
- Relay connection limits: semaphore (1024 max), idle timeout (5min), proper deadline propagation
- Cap SQL LIMIT to 1000 on connection history queries

## [0.4.0] - 2026-03-13

### Added
- **Split tunneling** — bypass VPN for selected domains and IP ranges, with UI controls in Settings
- **CDN/Cloudflare WebSocket transport** — VLESS over WebSocket for Cloudflare-fronted censorship circumvention
- **TCP relay/bridge mode** — `burrow-server relay` command forwards traffic to upstream server, masking real server IP
- **Connection fallback chain** — client auto-probes direct VLESS+Reality, falls back to CDN WebSocket if unreachable
- **HMAC-signed invites** — invite links are cryptographically signed to prevent tampering
- **Key validation** — Reality/WireGuard keys validated for correct length and format before use
- **Mobile scaffold** — Tauri 2 iOS/Android compilation targets with conditional desktop/mobile UI

### Changed
- Client tunnel engine refactored: transport mode selection (direct/CDN) at connection time
- DNS rules align with split tunneling bypass domains for leak-free operation
- Settings page adapts for mobile context (hides desktop-only proxy config)

## [0.3.0] - 2026-03-13

### Added
- **Auto-update** — checks GitHub releases for new versions on startup
- **Single instance** — prevents duplicate app windows, focuses existing window on relaunch
- **Window state persistence** — remembers window size and position across sessions
- **Comprehensive test suite** — 88+ frontend tests (vitest), 27 client Go tests, 15 server Go tests
- **CI test pipeline** — vitest and Go tests run on every push/PR

### Fixed
- **Critical: command injection in kill switch** — shell metacharacters in interface names now sanitized
- **Critical: CORS wildcard** — restricted to localhost/Tauri origins only
- **Critical: missing rate limiting on auth** — brute-force protection added
- **Critical: JSON injection in invite data** — input validation hardened
- **Race conditions** — atomic config writes, mutex-protected daemon state, safe HTTP timeouts
- **Frontend lifecycle** — proper cleanup of intervals/subscriptions, error boundaries in stores
- **Darwin kill switch** — uses validated interface names instead of shell interpolation

### Changed
- Server API now includes CORS middleware with proper origin validation
- SQLite store uses write-ahead logging for concurrent safety
- Go binaries include graceful shutdown handlers
- Crypto functions validate key lengths before operations

## [0.2.0] - 2026-03-13

### Added
- **VPN mode (TUN)** — routes all system traffic through VPN, no proxy setup needed
- **Kill switch** — blocks all internet if VPN drops (Linux/macOS/Windows)
- **Auto-reconnect** — exponential backoff, up to 10 attempts, cancel anytime
- **Live speed stats** — real-time upload/download speed with total traffic counters
- **Server ping** — TCP latency measurement with color-coded badges
- **Server switching** — switch servers while connected without manual disconnect
- **Desktop notifications** — system notifications on connect and disconnect
- **Dynamic system tray** — menu reflects connection state, tooltip shows status
- **Auto-connect** — automatic connection on app launch
- **Deep links** — `burrow://connect/...` URLs to add servers from browser
- **Onboarding wizard** — first-run flow guides new users through setup
- **Localization** — English, Russian, Chinese (auto-detected from system locale)
- **Persistent preferences** — settings saved with visual confirmation
- **Error localization** — daemon errors translated to user's language
- **Admin auto-refresh** — dashboard stats update every 5 seconds
- **Inline confirmations** — no browser `confirm()` dialogs in admin dashboard
- **Server ping endpoint** — `GET /api/servers/:name/ping` in client daemon API

### Fixed
- Silent error swallowing in client store — now shows daemon connection errors
- Race condition in reconnect loop — ghost tunnel after disconnect
- Mutex unlock/relock gap in reconnect cancel path
- CORS restricted to localhost/Tauri origins (was wildcard `*`)
- Deep link scheme corrected to `burrow://connect/` to match Go invite format
- Preference save before connect no longer silently swallowed
- Server switch attempts reconnect to previous server on failure
- Tray polling thread now exits cleanly on app shutdown
- No false "Connection failed" notification on app quit
- Clipboard API properly awaited with error handling
- JSON encode errors logged in Go daemon

### Changed
- Version bumped to 0.2.0 across all packages
- Go version requirement updated to 1.26+
- Release workflow updated to Go 1.26
- Admin dashboard uses typed TypeScript interfaces (no `any`)

## [0.1.0] - 2026-03-10

### Added
- Initial release
- VLESS+Reality protocol with sing-box engine
- Hysteria2 and Shadowsocks 2022 fallback protocols
- Server with admin dashboard, invite system, SQLite storage
- Desktop client with Tauri 2
- Docker deployment support
- CI/CD with GitHub Actions
