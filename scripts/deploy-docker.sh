#!/usr/bin/env bash
# Docker Compose deployment for Burrow VPN server on a fresh Ubuntu/Debian VPS.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/FrankFMY/burrow/main/scripts/deploy-docker.sh | bash -s -- --password <admin-password>
#   ./scripts/deploy-docker.sh --password <admin-password> --server <ip-address>

set -euo pipefail

REPO="FrankFMY/burrow"
DEPLOY_DIR="/opt/burrow"
CONFIG_DIR="${DEPLOY_DIR}/config"
CONTAINER_NAME="burrow-burrow-1"

# Defaults
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
Usage: deploy-docker.sh [OPTIONS]

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
        die "This script must be run as root. Use: sudo bash deploy-docker.sh ..."
    fi
}

# --- Install Docker ---

install_docker() {
    if command -v docker >/dev/null 2>&1; then
        log_info "Docker already installed: $(docker --version)"
    else
        log_step "Installing Docker via official install script..."
        curl -fsSL https://get.docker.com | sh
        systemctl enable --now docker
        log_info "Docker installed: $(docker --version)"
    fi

    if docker compose version >/dev/null 2>&1; then
        log_info "Docker Compose available: $(docker compose version --short)"
    else
        die "Docker Compose plugin not available. Install it: apt-get install docker-compose-plugin"
    fi
}

# --- Firewall ---

configure_firewall() {
    if ! command -v ufw >/dev/null 2>&1; then
        log_warn "ufw not found, skipping firewall configuration. Make sure ports ${PORT}, ${API_PORT}, 8443, 8388 are open."
        return
    fi

    log_step "Configuring firewall (ufw)..."

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

# --- Clone / download project files ---

setup_project() {
    log_step "Setting up project files in ${DEPLOY_DIR}..."

    mkdir -p "${DEPLOY_DIR}" "${CONFIG_DIR}"

    if command -v git >/dev/null 2>&1; then
        if [[ -d "${DEPLOY_DIR}/.git" ]]; then
            log_info "Repository already cloned, pulling latest changes..."
            git -C "${DEPLOY_DIR}" pull --ff-only || log_warn "git pull failed, using existing files"
        else
            # Clone into a temp dir and move, since DEPLOY_DIR already exists
            local tmp
            tmp=$(mktemp -d)
            git clone --depth 1 "https://github.com/${REPO}.git" "${tmp}/burrow"
            # Move everything except config (which we already created)
            cp -rn "${tmp}/burrow/." "${DEPLOY_DIR}/" 2>/dev/null || cp -r "${tmp}/burrow/." "${DEPLOY_DIR}/"
            rm -rf "${tmp}"
            log_info "Repository cloned to ${DEPLOY_DIR}"
        fi
    else
        log_step "git not found, installing..."
        apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1
        local tmp
        tmp=$(mktemp -d)
        git clone --depth 1 "https://github.com/${REPO}.git" "${tmp}/burrow"
        cp -rn "${tmp}/burrow/." "${DEPLOY_DIR}/" 2>/dev/null || cp -r "${tmp}/burrow/." "${DEPLOY_DIR}/"
        rm -rf "${tmp}"
        log_info "Repository cloned to ${DEPLOY_DIR}"
    fi
}

# --- Build and start containers ---

build_and_start() {
    log_step "Building and starting containers..."

    cd "${DEPLOY_DIR}"

    # Generate docker-compose.override.yml if custom ports are needed
    if [[ "${PORT}" -ne "${DEFAULT_PORT}" || "${API_PORT}" -ne "${DEFAULT_API_PORT}" ]]; then
        cat > "${DEPLOY_DIR}/docker-compose.override.yml" <<EOF
services:
  burrow:
    ports:
      - "${PORT}:443"
      - "${API_PORT}:8080"
      - "8443:8443"
      - "8388:8388"
EOF
        log_info "Created port override: ${PORT}->443, ${API_PORT}->8080"
    fi

    docker compose build
    docker compose up -d

    log_info "Containers started"
}

# --- Initialize server inside container ---

init_server() {
    if [[ -f "${CONFIG_DIR}/burrow-server.json" ]]; then
        log_warn "Config already exists at ${CONFIG_DIR}/burrow-server.json, skipping initialization."
        log_warn "Delete it to reinitialize."
        return
    fi

    log_step "Waiting for container to be ready..."
    local retries=0
    while ! docker compose -f "${DEPLOY_DIR}/docker-compose.yml" ps --format '{{.State}}' 2>/dev/null | grep -q "running"; do
        retries=$((retries + 1))
        if [[ "${retries}" -gt 15 ]]; then
            die "Container failed to start within 30s. Check: docker compose -f ${DEPLOY_DIR}/docker-compose.yml logs"
        fi
        sleep 2
    done

    local container
    container=$(docker compose -f "${DEPLOY_DIR}/docker-compose.yml" ps -q burrow 2>/dev/null)
    if [[ -z "${container}" ]]; then
        die "Cannot find burrow container. Check: docker compose -f ${DEPLOY_DIR}/docker-compose.yml ps"
    fi

    log_step "Initializing server configuration inside container..."

    # Stop the container since init needs to create the config and the run
    # command will fail without it. We exec init in a temporary container instead.
    docker compose -f "${DEPLOY_DIR}/docker-compose.yml" stop burrow

    docker compose -f "${DEPLOY_DIR}/docker-compose.yml" run --rm --no-deps \
        -e HOME=/tmp \
        burrow init \
        --password "${PASSWORD}" \
        --server "${SERVER}" \
        --port "${PORT}" \
        --api-port "${API_PORT}" \
        --data-dir /var/lib/burrow \
        --config /etc/burrow/burrow-server.json

    log_info "Server configuration created"

    # Restart with the new config
    docker compose -f "${DEPLOY_DIR}/docker-compose.yml" up -d
    log_info "Container restarted with configuration"
}

# --- Health check ---

health_check() {
    log_step "Verifying deployment..."

    local retries=0
    while true; do
        if curl -sf "http://localhost:${API_PORT}/health" >/dev/null 2>&1; then
            log_info "Health check passed"
            return
        fi
        retries=$((retries + 1))
        if [[ "${retries}" -gt 15 ]]; then
            log_warn "Health check did not pass within 30s. The server may still be starting."
            log_warn "Check: docker compose -f ${DEPLOY_DIR}/docker-compose.yml logs"
            return
        fi
        sleep 2
    done
}

# --- Summary ---

print_summary() {
    local admin_url="http://${SERVER}:${API_PORT}/admin"

    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  Burrow VPN Server deployed (Docker)       ${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "  Admin panel:    ${BLUE}${admin_url}${NC}"
    echo -e "  Admin password: (the one you provided via --password)"
    echo -e "  Config:         ${CONFIG_DIR}/burrow-server.json"
    echo -e "  Project dir:    ${DEPLOY_DIR}"
    echo ""
    echo -e "  Manage:"
    echo -e "    cd ${DEPLOY_DIR}"
    echo -e "    docker compose logs -f       # view logs"
    echo -e "    docker compose restart       # restart"
    echo -e "    docker compose down          # stop"
    echo -e "    docker compose up -d --build # rebuild and start"
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
    echo -e "${BLUE}Burrow VPN Server — Docker Deploy${NC}"
    echo ""

    require_root
    detect_os
    install_docker
    configure_firewall
    setup_project
    build_and_start
    init_server
    health_check
    print_summary
}

main
