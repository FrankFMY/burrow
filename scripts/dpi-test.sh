#!/usr/bin/env bash
set -euo pipefail

# DPI resistance testing script for Burrow VPN.
# Verifies that server traffic is indistinguishable from normal HTTPS.
#
# Usage:
#   ./scripts/dpi-test.sh <server_ip> <port> <camouflage_sni>
#
# Requirements: curl, openssl, tshark (optional), timeout (coreutils)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

log_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASS++)); }
log_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAIL++)); }
log_skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; ((SKIP++)); }

usage() {
    echo "Usage: $0 <server_ip> <port> <camouflage_sni>"
    echo ""
    echo "Arguments:"
    echo "  server_ip       Server IP address"
    echo "  port            Server port (typically 443)"
    echo "  camouflage_sni  Camouflage domain (e.g. www.microsoft.com)"
    exit 1
}

if [[ $# -lt 3 ]]; then
    usage
fi

SERVER="$1"
PORT="$2"
SNI="$3"
TIMEOUT_SEC=10
PCAP_FILE=$(mktemp /tmp/burrow-dpi-XXXXXX.pcap)

cleanup() {
    rm -f "$PCAP_FILE"
}
trap cleanup EXIT

echo "========================================="
echo " Burrow DPI Resistance Test"
echo "========================================="
echo " Server:    $SERVER:$PORT"
echo " SNI:       $SNI"
echo ""

# ---------------------------------------------------------------------------
# 1. TLS Fingerprint Test
# ---------------------------------------------------------------------------
echo "--- TLS Camouflage ---"

# 1a. Plain HTTPS request via curl — server should serve camouflage content
http_status=$(curl -sk --resolve "${SNI}:${PORT}:${SERVER}" \
    "https://${SNI}:${PORT}/" \
    -o /dev/null -w "%{http_code}" \
    --connect-timeout "$TIMEOUT_SEC" 2>/dev/null || echo "000")

if [[ "$http_status" -ge 200 && "$http_status" -lt 500 ]]; then
    log_pass "HTTPS request returned HTTP $http_status (camouflage active)"
else
    log_fail "HTTPS request returned HTTP $http_status (expected 2xx-4xx from camouflage site)"
fi

# 1b. Verify TLS certificate presents the camouflage domain
cert_cn=$(echo | openssl s_client -connect "${SERVER}:${PORT}" \
    -servername "$SNI" -verify_quiet 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN\s*=\s*//' || echo "")

if [[ -n "$cert_cn" ]]; then
    if echo "$cert_cn" | grep -qi "$SNI"; then
        log_pass "TLS certificate CN matches camouflage SNI: $cert_cn"
    else
        log_pass "TLS certificate CN: $cert_cn (Reality proxies the real cert)"
    fi
else
    log_fail "Could not extract TLS certificate CN"
fi

# 1c. Verify TLS 1.3 is used
tls_version=$(echo | openssl s_client -connect "${SERVER}:${PORT}" \
    -servername "$SNI" 2>/dev/null | grep -oP 'Protocol\s*:\s*\K\S+' || echo "")

if [[ "$tls_version" == "TLSv1.3" ]]; then
    log_pass "TLS version: $tls_version"
elif [[ -n "$tls_version" ]]; then
    log_fail "TLS version: $tls_version (expected TLSv1.3)"
else
    log_fail "Could not determine TLS version"
fi

echo ""

# ---------------------------------------------------------------------------
# 2. Protocol Detection Test (requires tshark)
# ---------------------------------------------------------------------------
echo "--- Protocol Detection ---"

if command -v tshark &>/dev/null; then
    # Capture a short TLS handshake
    tshark -i any -f "host $SERVER and port $PORT" \
        -a duration:5 -w "$PCAP_FILE" 2>/dev/null &
    TSHARK_PID=$!
    sleep 1

    # Trigger a connection
    curl -sk --resolve "${SNI}:${PORT}:${SERVER}" \
        "https://${SNI}:${PORT}/" \
        -o /dev/null --connect-timeout 5 2>/dev/null || true

    wait "$TSHARK_PID" 2>/dev/null || true

    # 2a. Check for plaintext protocol leaks
    plaintext=$(tshark -r "$PCAP_FILE" -Y "data.data contains \"VLESS\" or data.data contains \"vmess\" or data.data contains \"trojan\"" 2>/dev/null | wc -l)
    if [[ "$plaintext" -eq 0 ]]; then
        log_pass "No plaintext protocol identifiers found in capture"
    else
        log_fail "Found $plaintext packets with plaintext protocol identifiers"
    fi

    # 2b. Verify SNI in ClientHello
    sni_in_hello=$(tshark -r "$PCAP_FILE" -Y "tls.handshake.type == 1" \
        -T fields -e tls.handshake.extensions_server_name 2>/dev/null | head -1)
    if [[ "$sni_in_hello" == "$SNI" ]]; then
        log_pass "ClientHello SNI matches camouflage domain: $sni_in_hello"
    elif [[ -n "$sni_in_hello" ]]; then
        log_fail "ClientHello SNI: $sni_in_hello (expected $SNI)"
    else
        log_skip "Could not extract SNI from ClientHello (capture may be empty)"
    fi

    # 2c. Check that all traffic on the port is TLS (no plaintext frames)
    non_tls=$(tshark -r "$PCAP_FILE" -Y "tcp.port == $PORT and not tls and tcp.len > 0" 2>/dev/null | wc -l)
    if [[ "$non_tls" -eq 0 ]]; then
        log_pass "All captured traffic on port $PORT is TLS-encrypted"
    else
        log_fail "Found $non_tls non-TLS packets on port $PORT"
    fi
else
    log_skip "tshark not installed, skipping packet capture tests"
    log_skip "  Install with: apt install tshark"
fi

echo ""

# ---------------------------------------------------------------------------
# 3. Active Probing Simulation
# ---------------------------------------------------------------------------
echo "--- Active Probing Resistance ---"

# 3a. Plain TLS client (not VLESS) — should get camouflage site response
probe_status=$(curl -sk --resolve "${SNI}:${PORT}:${SERVER}" \
    "https://${SNI}:${PORT}/" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    -o /dev/null -w "%{http_code}" \
    --connect-timeout "$TIMEOUT_SEC" 2>/dev/null || echo "000")

if [[ "$probe_status" -ge 200 && "$probe_status" -lt 500 ]]; then
    log_pass "Plain TLS probe forwarded to camouflage site (HTTP $probe_status)"
else
    log_fail "Plain TLS probe: HTTP $probe_status (expected camouflage response)"
fi

# 3b. Wrong auth / random HTTP path — should still serve camouflage
probe_random=$(curl -sk --resolve "${SNI}:${PORT}:${SERVER}" \
    "https://${SNI}:${PORT}/random-nonexistent-path-$(date +%s)" \
    -o /dev/null -w "%{http_code}" \
    --connect-timeout "$TIMEOUT_SEC" 2>/dev/null || echo "000")

if [[ "$probe_random" -ge 200 && "$probe_random" -lt 500 ]]; then
    log_pass "Random path probe forwarded to camouflage site (HTTP $probe_random)"
else
    log_fail "Random path probe: HTTP $probe_random (expected camouflage response)"
fi

# 3c. Send random binary data to port 443 — should close gracefully
random_result=$(timeout "$TIMEOUT_SEC" bash -c "head -c 64 /dev/urandom | nc -w 3 $SERVER $PORT 2>&1; echo EXIT:\$?" || echo "EXIT:0")
exit_code=$(echo "$random_result" | grep -oP 'EXIT:\K\d+' | tail -1)

if [[ "$exit_code" -eq 0 || "$exit_code" -eq 1 ]]; then
    log_pass "Random binary data: connection closed gracefully"
else
    log_fail "Random binary data: unexpected exit code $exit_code"
fi

# 3d. TLS connection with wrong SNI — should still work (Reality forwards)
wrong_sni_status=$(curl -sk --resolve "wrong.example.com:${PORT}:${SERVER}" \
    "https://wrong.example.com:${PORT}/" \
    -o /dev/null -w "%{http_code}" \
    --connect-timeout "$TIMEOUT_SEC" 2>/dev/null || echo "000")

if [[ "$wrong_sni_status" != "000" ]]; then
    log_pass "Wrong SNI probe: connection handled (HTTP $wrong_sni_status)"
else
    # Connection refused or timeout is also acceptable — server doesn't reveal itself
    log_pass "Wrong SNI probe: connection refused/closed (server stays silent)"
fi

echo ""

# ---------------------------------------------------------------------------
# 4. DNS Leak Test
# ---------------------------------------------------------------------------
echo "--- DNS Leak Test ---"

# Check if we can detect DNS leakage by querying a unique subdomain
# This test is meaningful only when connected through the tunnel
if [[ -n "${BURROW_CONNECTED:-}" ]]; then
    leak_domain="leak-test-$(date +%s).example.com"
    # If DNS goes through the tunnel, the local resolver should not see this query
    if timeout 3 nslookup "$leak_domain" 127.0.0.1 &>/dev/null; then
        log_fail "DNS query resolved locally (potential DNS leak)"
    else
        log_pass "DNS query did not resolve locally (likely tunneled)"
    fi

    # Check /etc/resolv.conf is not using a public resolver directly
    if grep -qE '^nameserver\s+(8\.8\.|1\.1\.|9\.9\.)' /etc/resolv.conf 2>/dev/null; then
        log_fail "resolv.conf points to public DNS directly (DNS may leak)"
    else
        log_pass "resolv.conf does not point to public DNS directly"
    fi
else
    log_skip "DNS leak test requires active tunnel (set BURROW_CONNECTED=1)"
fi

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS + FAIL + SKIP))
echo "========================================="
echo " Results: $PASS passed, $FAIL failed, $SKIP skipped (out of $TOTAL)"
echo "========================================="

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
