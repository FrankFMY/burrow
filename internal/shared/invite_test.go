package shared

import (
	"testing"
)

func TestEncodeDecodeInvite(t *testing.T) {
	original := InviteData{
		Server:    "103.24.55.12",
		Port:      443,
		Token:     "550e8400-e29b-41d4-a716-446655440000",
		SNI:       "www.microsoft.com",
		PublicKey: "base64-server-reality-public-key",
		ShortID:   "abcd1234",
		Name:      "My Phone",
	}

	link, err := EncodeInvite(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if link[:len(InviteScheme)] != InviteScheme {
		t.Fatalf("link should start with %s, got %s", InviteScheme, link[:20])
	}

	decoded, err := DecodeInvite(link)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Server != original.Server {
		t.Errorf("server: got %q, want %q", decoded.Server, original.Server)
	}
	if decoded.Port != original.Port {
		t.Errorf("port: got %d, want %d", decoded.Port, original.Port)
	}
	if decoded.Token != original.Token {
		t.Errorf("token: got %q, want %q", decoded.Token, original.Token)
	}
	if decoded.SNI != original.SNI {
		t.Errorf("sni: got %q, want %q", decoded.SNI, original.SNI)
	}
	if decoded.PublicKey != original.PublicKey {
		t.Errorf("public key: got %q, want %q", decoded.PublicKey, original.PublicKey)
	}
	if decoded.ShortID != original.ShortID {
		t.Errorf("short id: got %q, want %q", decoded.ShortID, original.ShortID)
	}
	if decoded.Name != original.Name {
		t.Errorf("name: got %q, want %q", decoded.Name, original.Name)
	}
}

func TestEncodeDecodeInviteWithCDN(t *testing.T) {
	original := InviteData{
		Server:    "103.24.55.12",
		Port:      443,
		Token:     "550e8400-e29b-41d4-a716-446655440000",
		SNI:       "www.microsoft.com",
		PublicKey: "base64-server-reality-public-key",
		ShortID:   "abcd1234",
		Name:      "CDN Phone",
		CDNHost:   "cdn.example.com",
		CDNPort:   443,
		CDNPath:   "/ws",
	}

	link, err := EncodeInvite(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := DecodeInvite(link)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.CDNHost != original.CDNHost {
		t.Errorf("cdn_host: got %q, want %q", decoded.CDNHost, original.CDNHost)
	}
	if decoded.CDNPort != original.CDNPort {
		t.Errorf("cdn_port: got %d, want %d", decoded.CDNPort, original.CDNPort)
	}
	if decoded.CDNPath != original.CDNPath {
		t.Errorf("cdn_path: got %q, want %q", decoded.CDNPath, original.CDNPath)
	}
}

func TestEncodeDecodeInviteWithoutCDN(t *testing.T) {
	original := InviteData{
		Server:    "103.24.55.12",
		Port:      443,
		Token:     "token-123",
		SNI:       "www.microsoft.com",
		PublicKey: "pubkey",
		ShortID:   "abcd",
	}

	link, err := EncodeInvite(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := DecodeInvite(link)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.CDNHost != "" {
		t.Errorf("cdn_host should be empty, got %q", decoded.CDNHost)
	}
	if decoded.CDNPort != 0 {
		t.Errorf("cdn_port should be 0, got %d", decoded.CDNPort)
	}
	if decoded.CDNPath != "" {
		t.Errorf("cdn_path should be empty, got %q", decoded.CDNPath)
	}
}

func TestDecodeInviteInvalidScheme(t *testing.T) {
	_, err := DecodeInvite("https://example.com")
	if err == nil {
		t.Fatal("expected error for invalid scheme")
	}
}

func TestDecodeInviteInvalidBase64(t *testing.T) {
	_, err := DecodeInvite(InviteScheme + "!!!invalid!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}
