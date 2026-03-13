package server

import (
	"testing"
)

func TestBuildVLESSWebSocketInbound(t *testing.T) {
	cfg := &ServerConfig{
		CDNWebSocket: &CDNWebSocketConfig{
			Enabled: true,
			Port:    8080,
			Path:    "/ws",
			Host:    "cdn.example.com",
		},
	}
	users := []map[string]string{
		{"name": "Alice", "uuid": "uuid-1"},
		{"name": "Bob", "uuid": "uuid-2"},
	}

	result := buildVLESSWebSocketInbound(cfg, users)

	if result["type"] != "vless" {
		t.Errorf("type: got %v, want %q", result["type"], "vless")
	}
	if result["tag"] != "vless-ws-in" {
		t.Errorf("tag: got %v, want %q", result["tag"], "vless-ws-in")
	}
	if result["listen"] != "::" {
		t.Errorf("listen: got %v, want %q", result["listen"], "::")
	}
	if result["listen_port"] != uint16(8080) {
		t.Errorf("listen_port: got %v, want 8080", result["listen_port"])
	}

	resultUsers, ok := result["users"].([]map[string]string)
	if !ok {
		t.Fatal("users should be []map[string]string")
	}
	if len(resultUsers) != 2 {
		t.Errorf("users count: got %d, want 2", len(resultUsers))
	}

	transport, ok := result["transport"].(map[string]any)
	if !ok {
		t.Fatal("transport should be map[string]any")
	}
	if transport["type"] != "ws" {
		t.Errorf("transport type: got %v, want %q", transport["type"], "ws")
	}
	if transport["path"] != "/ws" {
		t.Errorf("transport path: got %v, want %q", transport["path"], "/ws")
	}

	if _, hasTLS := result["tls"]; hasTLS {
		t.Error("WebSocket inbound should not have TLS (Cloudflare terminates TLS)")
	}
}

func TestBuildVLESSWebSocketInboundCustomPath(t *testing.T) {
	cfg := &ServerConfig{
		CDNWebSocket: &CDNWebSocketConfig{
			Enabled: true,
			Port:    9090,
			Path:    "/custom-path",
			Host:    "cdn.example.com",
		},
	}
	users := []map[string]string{
		{"name": "User1", "uuid": "uuid-1"},
	}

	result := buildVLESSWebSocketInbound(cfg, users)

	if result["listen_port"] != uint16(9090) {
		t.Errorf("listen_port: got %v, want 9090", result["listen_port"])
	}

	transport := result["transport"].(map[string]any)
	if transport["path"] != "/custom-path" {
		t.Errorf("transport path: got %v, want %q", transport["path"], "/custom-path")
	}
}
