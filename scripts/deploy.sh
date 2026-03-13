#!/usr/bin/env bash
# One-command deployment for Burrow VPN server on a fresh Ubuntu/Debian VPS.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/FrankFMY/burrow/main/scripts/deploy.sh | bash -s -- --password <admin-password> --domain <your-domain>
#   curl -sL https://raw.githubusercontent.com/FrankFMY/burrow/main/scripts/deploy.sh | bash -s -- --password <admin-password> --server <ip-address>
#   ./scripts/deploy.sh --password <admin-password> --server <ip-address>

set -euo pipefail

REPO="FrankFMY/burrow"
BINARY="burrow-server"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/burrow"
CONFIG_PATH="${CONFIG_DIR}/burrow-server.json"
DATA_DIR="/var/lib/burrow"
SERVICE_NAME="burrow-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Defaults matching internal/server/config.go
DEFAULT_PORT=443
DEFAULT_API_PORT=8080

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()    { echo -e "${BLUE}[>>]${NC} $*"; }

die() { log_error "$*"; exit 1; }

# --- Argument parsing ---

PASSWORD=""
SERVER=""
DOMAIN=""
PORT="${DEFAULT_PORT}"
API_PORT="${DEFAULT_API_PORT}"

usage() {
    cat <<'EOF'
Usage: deploy.sh [OPTIONS]

Required:
  --password <pwd>       Admin panel password

Server address (at least one):
  --server <ip>          Server public IP address
  --domain <fqdn>        Server domain name (implies DNS A record must exist)

Optional:
  --port <port>          VLESS+Reality listen port (default: 443)
  --api-port <port>      Admin API port (default: 8080)
  -h, --help             Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --password)  PASSWORD="$2";  shift 2 ;;
        --server)    SERVER="$2";    shift 2 ;;
        --domain)    DOMAIN="$2";    shift 2 ;;
        --port)      PORT="$2";      shift 2 ;;
        --api-port)  API_PORT="$2";  shift 2 ;;
        -h|--help)   usage ;;
        *) die "Unknown option: $1. Use --help for usage." ;;
    esac
done

# --- Validation ---

[[ -z "${PASSWORD}" ]] && die "--password is required"

if [[ -z "${SERVER}" && -z "${DOMAIN}" ]]; then
    log_step "No --server or --domain provided, detecting public IP..."
    SERVER=$(curl -s4 --connect-timeout 10 ifconfig.me 2>/dev/null || true)
    if [[ -z "${SERVER}" ]]; then
        SERVER=$(curl -s4 --connect-timeout 10 icanhazip.com 2>/dev/null || true)
    fi
    [[ -z "${SERVER}" ]] && die "Failed to auto-detect public IP. Provide --server <ip> or --domain <fqdn>."
    log_info "Detected public IP: ${SERVER}"
fi

# If domain is given, use it as server address
if [[ -n "${DOMAIN}" ]]; then
    SERVER="${DOMAIN}"
fi

# --- OS detection ---

detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot detect OS. /etc/os-release not found. This script supports Ubuntu 22.04+ and Debian 12+."
    fi

    # shellcheck source=/dev/null
    . /etc/os-release

    case "${ID}" in
        ubuntu)
            local major
            major=$(echo "${VERSION_ID}" | cut -d. -f1)
            if [[ "${major}" -lt 22 ]]; then
                die "Ubuntu ${VERSION_ID} is not supported. Minimum: 22.04"
            fi
            ;;
        debian)
            local major
            major=$(echo "${VERSION_ID}" | cut -d. -f1)
            if [[ "${major}" -lt 12 ]]; then
                die "Debian ${VERSION_ID} is not supported. Minimum: 12"
            fi
            ;;
        *)
            die "Unsupported OS: ${ID}. This script supports Ubuntu 22.04+ and Debian 12+."
            ;;
    esac

    log_info "Detected OS: ${PRETTY_NAME}"
}

# --- Root check ---

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "This script must be run as root. Use: sudo bash deploy.sh ..."
    fi
}

# --- Install dependencies ---

install_binary() {
    log_step "Installing ${BINARY} from latest GitHub release..."

    local arch
    arch=$(uname -m)
    case "${arch}" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) die "Unsupported architecture: ${arch}" ;;
    esac

    local version
    version=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
    if [[ -z "${version}" ]]; then
        die "Failed to fetch latest release from GitHub. Check network connectivity."
    fi

    local tarball="${BINARY}_linux_${arch}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${version}/${tarball}"
    local checksums_url="https://github.com/${REPO}/releases/download/${version}/checksums.txt"

    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "${tmp}"' EXIT

    log_step "Downloading ${BINARY} ${version} (linux/${arch})..."
    curl -sfL "${url}" -o "${tmp}/${tarball}" || die "Failed to download ${url}"
    curl -sfL "${checksums_url}" -o "${tmp}/checksums.txt" || die "Failed to download checksums"

    local expected actual
    expected=$(grep "${tarball}" "${tmp}/checksums.txt" | cut -d' ' -f1)
    if [[ -z "${expected}" ]]; then
        die "Checksum for ${tarball} not found in checksums.txt"
    fi

    actual=$(sha256sum "${tmp}/${tarball}" | cut -d' ' -f1)
    if [[ "${actual}" != "${expected}" ]]; then
        die "Checksum verification failed! Expected: ${expected}, Got: ${actual}"
    fi
    log_info "Checksum verified"

    tar xz -C "${tmp}" -f "${tmp}/${tarball}"
    install -m 0755 "${tmp}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    # Remove trap since we clean up now
    rm -rf "${tmp}"
    trap - EXIT

    log_info "Installed ${INSTALL_DIR}/${BINARY} (${version})"
}

# --- Firewall ---

configure_firewall() {
    if ! command -v ufw >/dev/null 2>&1; then
        log_warn "ufw not found, skipping firewall configuration. Make sure ports ${PORT}, ${API_PORT}, 8443, 8388 are open."
        return
    fi

    log_step "Configuring firewall (ufw)..."

    # Ensure SSH is allowed before enabling
    ufw allow ssh >/dev/null 2>&1 || true

    local ports=("${PORT}" "${API_PORT}" 8443 8388)
    for p in "${ports[@]}"; do
        ufw allow "${p}/tcp" >/dev/null 2>&1 || true
        ufw allow "${p}/udp" >/dev/null 2>&1 || true
    done

    if ufw status | grep -q "inactive"; then
        ufw --force enable >/dev/null 2>&1 || true
    fi

    log_info "Firewall configured: ports ${ports[*]} opened"
}

# --- Initialize server ---

init_server() {
    if [[ -f "${CONFIG_PATH}" ]]; then
        log_warn "Config already exists at ${CONFIG_PATH}, skipping initialization."
        log_warn "Delete ${CONFIG_PATH} to reinitialize."
        return
    fi

    log_step "Initializing server configuration..."

    mkdir -p "${CONFIG_DIR}" "${DATA_DIR}"

    "${INSTALL_DIR}/${BINARY}" init \
        --password "${PASSWORD}" \
        --server "${SERVER}" \
        --port "${PORT}" \
        --api-port "${API_PORT}" \
        --data-dir "${DATA_DIR}" \
        --config "${CONFIG_PATH}"

    log_info "Server configuration created at ${CONFIG_PATH}"
}

# --- Systemd service ---

install_service() {
    log_step "Setting up systemd service..."

    if [[ -f "${SERVICE_FILE}" ]]; then
        log_warn "Service file ${SERVICE_FILE} already exists, overwriting."
    fi

    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Burrow VPN Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY} run --config ${CONFIG_PATH}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "Systemd service installed"
}

start_service() {
    log_step "Starting ${SERVICE_NAME}..."
    systemctl enable --now "${SERVICE_NAME}"
    sleep 2

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log_info "${SERVICE_NAME} is running"
    else
        log_error "${SERVICE_NAME} failed to start. Check: journalctl -u ${SERVICE_NAME} -n 50"
        exit 1
    fi
}

# --- Summary ---

print_summary() {
    local admin_url="http://${SERVER}:${API_PORT}/admin"

    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  Burrow VPN Server deployed successfully   ${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "  Admin panel:    ${BLUE}${admin_url}${NC}"
    echo -e "  Admin password: (the one you provided via --password)"
    echo -e "  Config:         ${CONFIG_PATH}"
    echo -e "  Service:        systemctl status ${SERVICE_NAME}"
    echo -e "  Logs:           journalctl -u ${SERVICE_NAME} -f"
    echo ""
    echo -e "  Ports open:     ${PORT} (VLESS+Reality), ${API_PORT} (API), 8443 (Hysteria2), 8388 (SS2022)"
    echo ""

    if [[ -n "${DOMAIN}" ]]; then
        echo -e "${YELLOW}  NOTE: Make sure DNS A record for '${DOMAIN}' points to this server's IP.${NC}"
        echo ""
    fi

    echo -e "  ${GREEN}Next step:${NC} Open the admin panel and create an invite."
    echo ""
}

# --- Main ---

main() {
    echo ""
    echo -e "${BLUE}Burrow VPN Server — Auto Deploy${NC}"
    echo ""

    require_root
    detect_os
    install_binary
    configure_firewall
    init_server
    install_service
    start_service
    print_summary
}

main
