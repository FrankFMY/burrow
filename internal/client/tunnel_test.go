package client

import (
	"encoding/json"
	"testing"

	"github.com/FrankFMY/burrow/internal/shared"
)

func TestBuildClientOptionsWithCDN(t *testing.T) {
	invite := shared.InviteData{
		Server:    "1.2.3.4",
		Port:      443,
		Token:     "test-uuid",
		SNI:       "www.microsoft.com",
		PublicKey: "test-pubkey",
		ShortID:   "abcd1234",
		CDNHost:   "cdn.example.com",
		CDNPort:   443,
		CDNPath:   "/ws",
	}

	configMap := buildClientConfigMap(invite, false, nil)

	outbounds, ok := configMap["outbounds"].([]any)
	if !ok {
		t.Fatal("outbounds should be []any")
	}

	if len(outbounds) != 3 {
		t.Fatalf("expected 3 outbounds (vless-out, vless-cdn-out, direct-out), got %d", len(outbounds))
	}

	cdnOutbound, ok := outbounds[1].(map[string]any)
	if !ok {
		t.Fatal("cdn outbound should be map[string]any")
	}
	if cdnOutbound["tag"] != "vless-cdn-out" {
		t.Errorf("cdn outbound tag: got %v, want %q", cdnOutbound["tag"], "vless-cdn-out")
	}
	if cdnOutbound["server"] != "cdn.example.com" {
		t.Errorf("cdn outbound server: got %v, want %q", cdnOutbound["server"], "cdn.example.com")
	}
	if cdnOutbound["server_port"] != uint16(443) {
		t.Errorf("cdn outbound server_port: got %v, want 443", cdnOutbound["server_port"])
	}
	if cdnOutbound["uuid"] != "test-uuid" {
		t.Errorf("cdn outbound uuid: got %v, want %q", cdnOutbound["uuid"], "test-uuid")
	}

	transport, ok := cdnOutbound["transport"].(map[string]any)
	if !ok {
		t.Fatal("cdn outbound should have transport")
	}
	if transport["type"] != "ws" {
		t.Errorf("transport type: got %v, want %q", transport["type"], "ws")
	}
	if transport["path"] != "/ws" {
		t.Errorf("transport path: got %v, want %q", transport["path"], "/ws")
	}

	headers, ok := transport["headers"].(map[string]any)
	if !ok {
		t.Fatal("transport should have headers")
	}
	if headers["Host"] != "cdn.example.com" {
		t.Errorf("transport Host header: got %v, want %q", headers["Host"], "cdn.example.com")
	}

	tls, ok := cdnOutbound["tls"].(map[string]any)
	if !ok {
		t.Fatal("cdn outbound should have tls")
	}
	if tls["enabled"] != true {
		t.Error("tls should be enabled")
	}
	if tls["server_name"] != "cdn.example.com" {
		t.Errorf("tls server_name: got %v, want %q", tls["server_name"], "cdn.example.com")
	}
}

func TestBuildClientOptionsWithoutCDN(t *testing.T) {
	invite := shared.InviteData{
		Server:    "1.2.3.4",
		Port:      443,
		Token:     "test-uuid",
		SNI:       "www.microsoft.com",
		PublicKey: "test-pubkey",
		ShortID:   "abcd1234",
	}

	configMap := buildClientConfigMap(invite, false, nil)

	outbounds, ok := configMap["outbounds"].([]any)
	if !ok {
		t.Fatal("outbounds should be []any")
	}

	if len(outbounds) != 2 {
		t.Fatalf("expected 2 outbounds (vless-out, direct-out), got %d", len(outbounds))
	}

	vlessOut := outbounds[0].(map[string]any)
	if vlessOut["tag"] != "vless-out" {
		t.Errorf("first outbound tag: got %v, want %q", vlessOut["tag"], "vless-out")
	}

	directOut := outbounds[1].(map[string]any)
	if directOut["tag"] != "direct-out" {
		t.Errorf("second outbound tag: got %v, want %q", directOut["tag"], "direct-out")
	}
}

func TestBuildClientOptionsCDNDefaultPort(t *testing.T) {
	invite := shared.InviteData{
		Server:    "1.2.3.4",
		Port:      443,
		Token:     "test-uuid",
		SNI:       "www.microsoft.com",
		PublicKey: "test-pubkey",
		ShortID:   "abcd1234",
		CDNHost:   "cdn.example.com",
		CDNPort:   0,
		CDNPath:   "",
	}

	configMap := buildClientConfigMap(invite, false, nil)

	outbounds := configMap["outbounds"].([]any)
	if len(outbounds) != 3 {
		t.Fatalf("expected 3 outbounds, got %d", len(outbounds))
	}

	cdnOutbound := outbounds[1].(map[string]any)
	if cdnOutbound["server_port"] != uint16(443) {
		t.Errorf("default cdn port: got %v, want 443", cdnOutbound["server_port"])
	}

	transport := cdnOutbound["transport"].(map[string]any)
	if transport["path"] != "/ws" {
		t.Errorf("default cdn path: got %v, want %q", transport["path"], "/ws")
	}
}

func TestBuildClientOptionsConfigMapSerializable(t *testing.T) {
	invite := shared.InviteData{
		Server:    "1.2.3.4",
		Port:      443,
		Token:     "test-uuid",
		SNI:       "www.microsoft.com",
		PublicKey: "test-pubkey",
		ShortID:   "abcd1234",
		CDNHost:   "cdn.example.com",
		CDNPort:   443,
		CDNPath:   "/ws",
	}

	configMap := buildClientConfigMap(invite, false, nil)

	b, err := json.Marshal(configMap)
	if err != nil {
		t.Fatalf("config map should be JSON serializable: %v", err)
	}
	if len(b) == 0 {
		t.Error("serialized config should not be empty")
	}
}
