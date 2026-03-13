# Burrow Threat Model

## Adversary Capabilities

Burrow is designed to resist the following adversary capabilities, ordered by increasing sophistication:

1. **Passive DPI (Deep Packet Inspection)**: The adversary inspects packet headers, sizes, and timing on the wire. This is the most common censorship technique deployed at national scale (GFW, TSPU, etc).

2. **Active Probing**: The adversary connects to suspected proxy servers and attempts to identify the protocol by sending crafted requests. If the server responds differently to probes vs legitimate traffic, the server is flagged.

3. **DNS Manipulation**: The adversary intercepts, redirects, or poisons DNS queries to block resolution of proxy-related domains or to identify users attempting to reach them.

4. **IP Blocking**: The adversary maintains blocklists of known proxy server IPs, CDN ranges, or entire ASNs. IPs can be discovered through active scanning, user traffic analysis, or intelligence sharing.

5. **TLS Fingerprinting**: The adversary compares the TLS ClientHello fingerprint (JA3/JA4) against known browser fingerprints. Non-browser fingerprints indicate proxy or VPN usage.

## What Burrow Protects Against

### Traffic Analysis (Passive DPI)

- **VLESS+Reality**: All traffic is wrapped in a TLS 1.3 session that is cryptographically indistinguishable from a legitimate HTTPS connection to the camouflage domain. The server uses the real certificate from the target domain via the Reality protocol, so even certificate inspection reveals nothing unusual.
- **No protocol identifiers**: VLESS produces no plaintext headers or magic bytes on the wire. Unlike older protocols (OpenVPN, PPTP, L2TP), there is no detectable handshake signature.
- **Standard packet sizes**: TLS record layer framing produces packet sizes consistent with normal HTTPS browsing.

### Protocol Detection (Active Probing)

- **Transparent forwarding**: When a non-VLESS client connects (including active probes), the server forwards the connection to the real camouflage domain. The probe sees a real website, not an error or connection reset.
- **No authentication error distinction**: Invalid credentials result in the same behavior as no credentials — forwarding to the camouflage site. The server never reveals it is a proxy.
- **Random data handling**: Non-TLS connections are closed without any identifying response.

### TLS Fingerprinting

- **uTLS with Chrome fingerprint**: The client uses uTLS to produce a ClientHello that matches the latest Chrome browser fingerprint. JA3/JA4 hashes are indistinguishable from real Chrome traffic.
- **SNI matches camouflage**: The SNI field in ClientHello contains the camouflage domain (e.g., `www.microsoft.com`), not a proxy-related domain.

### DNS Manipulation

- **Encrypted DNS through tunnel**: When connected, DNS queries use DoH (DNS-over-HTTPS) through the VPN tunnel via Cloudflare (1.1.1.1). Local DNS is not used for tunneled traffic.
- **Kill switch**: Optional kill switch prevents DNS leaks if the tunnel drops unexpectedly.
- **Split tunnel DNS**: When split tunneling is enabled, only bypassed domains resolve through local DNS; everything else goes through the tunnel.

### CDN Fronting (Fallback)

- **WebSocket over CDN**: When direct connection is blocked, Burrow can route traffic through CDN WebSocket connections. The adversary sees traffic to a CDN IP, which is shared by millions of legitimate websites.
- **Automatic fallback**: The client probes the direct server first and falls back to CDN transport if unreachable.

## What Burrow Does NOT Protect Against

### Endpoint Compromise

If the adversary has access to the client device or the server, all bets are off. Burrow encrypts traffic in transit; it does not protect against local malware, keyloggers, or server-side compromise.

### Timing Analysis at Scale

A sufficiently resourced adversary correlating traffic timing between a user and a suspected proxy server can statistically confirm usage. This requires monitoring both endpoints simultaneously and is typically a targeted attack, not a mass surveillance technique.

### Traffic Volume Patterns

While individual packets look like HTTPS, the overall traffic pattern (sustained high-bandwidth, long-duration sessions to a single IP) can suggest VPN usage. This is a statistical indicator, not a definitive one — video streaming and large downloads produce similar patterns.

### Server IP Discovery

If the server IP is discovered (through intelligence, social engineering, or enumeration), it can be blocked regardless of protocol camouflage. Mitigations:
- CDN fronting hides the real server IP behind shared CDN infrastructure.
- Relay chains add an extra hop, but the relay IP becomes the new target.
- IP rotation is not currently automated.

### Targeted Attacks with Prior Knowledge

If the adversary already knows the exact server IP, port, camouflage domain, and protocol in use, they can construct specific detection rules. Reality makes this harder (they still see a real website), but not impossible with enough prior knowledge.

### CDN-Level Blocking

CDN fronting depends on the CDN not blocking proxy traffic. Some CDNs actively detect and block domain fronting. If the CDN terminates the connection, the fallback transport fails. This is an arms race with CDN policies.

## Protocol Security Properties

| Property | VLESS+Reality | VLESS+WS (CDN) | Hysteria2 | SS2022 |
|---|---|---|---|---|
| DPI resistance | Excellent | Good | Moderate | Good |
| Active probe resistance | Excellent | Moderate | Low | N/A |
| TLS fingerprint | Chrome (uTLS) | Standard TLS | QUIC-based | N/A |
| Camouflage | Real domain cert | CDN domain | Self-signed | None |
| Fallback on block | Via CDN | N/A | N/A | N/A |

### VLESS+Reality (Primary)

- TLS 1.3 handshake with real certificate from camouflage domain
- Curve25519 key exchange for authentication (short_id + public_key)
- Non-authenticated connections transparently forwarded to camouflage site
- JA3 fingerprint matches Chrome via uTLS

### VLESS+WebSocket (CDN Fallback)

- Standard TLS to CDN edge
- WebSocket transport on configurable path
- Traffic appears as normal HTTPS to CDN domain
- No Reality (CDN terminates TLS), relies on CDN trust

### Hysteria2 (Speed-Optimized)

- QUIC-based, requires separate port and real TLS certificate
- Less censorship-resistant: QUIC itself is sometimes blocked
- Useful in environments where QUIC is allowed but TCP is throttled

### Shadowsocks 2022

- Stream cipher (2022-blake3-aes-256-gcm), no TLS wrapper
- Resistant to replay attacks
- Less camouflage than Reality — traffic is encrypted but not disguised as HTTPS

## Known Limitations

1. **Single server IP**: If the primary server IP is blocked, only CDN fallback remains. No automatic IP rotation.
2. **CDN dependency**: CDN fallback requires CDN cooperation. Domain fronting is increasingly restricted by major CDNs.
3. **uTLS lag**: Chrome updates its TLS fingerprint periodically. uTLS fingerprints may lag behind, creating a window where the fingerprint is slightly outdated.
4. **No post-quantum**: Current key exchange (Curve25519) is not quantum-resistant. TLS 1.3 with Reality inherits this limitation.
5. **Server metadata**: While traffic content is hidden, connection metadata (destination IP, connection duration, volume) is visible to the local ISP.
6. **WireGuard visibility**: The optional WireGuard inbound uses a well-known protocol on a standard port — it provides no DPI resistance and is included only for compatibility.
