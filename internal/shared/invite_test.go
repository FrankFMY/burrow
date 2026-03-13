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

func TestSignAndVerifyInvite(t *testing.T) {
	secret := "test-hmac-secret-key"
	data := InviteData{
		Server:    "10.0.0.1",
		Port:      443,
		Token:     "test-token-uuid",
		SNI:       "www.microsoft.com",
		PublicKey: "test-public-key",
		ShortID:   "abcd1234",
		Name:      "Test Client",
	}

	sig := SignInvite(data, secret)
	if sig == "" {
		t.Fatal("signature should not be empty")
	}

	data.Sig = sig
	link, err := EncodeInvite(data)
	if err != nil {
		t.Fatalf("encode signed invite: %v", err)
	}

	verified, err := VerifyInvite(link, secret)
	if err != nil {
		t.Fatalf("verify invite: %v", err)
	}
	if verified.Token != data.Token {
		t.Errorf("token: got %q, want %q", verified.Token, data.Token)
	}
	if verified.Server != data.Server {
		t.Errorf("server: got %q, want %q", verified.Server, data.Server)
	}
}

func TestVerifyInviteInvalidSignature(t *testing.T) {
	secret := "correct-secret"
	data := InviteData{
		Server:    "10.0.0.1",
		Port:      443,
		Token:     "test-token",
		SNI:       "www.example.com",
		PublicKey: "pk",
		ShortID:   "1234",
		Sig:       "tampered-signature-value",
	}

	link, err := EncodeInvite(data)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	_, err = VerifyInvite(link, secret)
	if err == nil {
		t.Fatal("should reject invalid signature")
	}
}

func TestVerifyInviteWrongSecret(t *testing.T) {
	data := InviteData{
		Server:    "10.0.0.1",
		Port:      443,
		Token:     "test-token",
		SNI:       "www.example.com",
		PublicKey: "pk",
		ShortID:   "1234",
	}

	data.Sig = SignInvite(data, "secret-1")
	link, err := EncodeInvite(data)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	_, err = VerifyInvite(link, "secret-2")
	if err == nil {
		t.Fatal("should reject invite signed with different secret")
	}
}

func TestVerifyInviteBackwardCompatibility(t *testing.T) {
	data := InviteData{
		Server:    "10.0.0.1",
		Port:      443,
		Token:     "old-token",
		SNI:       "www.example.com",
		PublicKey: "pk",
		ShortID:   "1234",
	}

	link, err := EncodeInvite(data)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	verified, err := VerifyInvite(link, "any-secret")
	if err != nil {
		t.Fatalf("old invites without sig should pass: %v", err)
	}
	if verified.Token != "old-token" {
		t.Errorf("token: got %q, want %q", verified.Token, "old-token")
	}
}

func TestSignInviteDeterministic(t *testing.T) {
	data := InviteData{
		Server:    "10.0.0.1",
		Port:      443,
		Token:     "test-token",
		SNI:       "www.example.com",
		PublicKey: "pk",
		ShortID:   "1234",
	}

	sig1 := SignInvite(data, "secret")
	sig2 := SignInvite(data, "secret")
	if sig1 != sig2 {
		t.Error("HMAC should be deterministic for same input and key")
	}
}

func TestSignInviteDifferentSecrets(t *testing.T) {
	data := InviteData{
		Server:    "10.0.0.1",
		Port:      443,
		Token:     "test-token",
		SNI:       "www.example.com",
		PublicKey: "pk",
		ShortID:   "1234",
	}

	sig1 := SignInvite(data, "secret-a")
	sig2 := SignInvite(data, "secret-b")
	if sig1 == sig2 {
		t.Error("different secrets should produce different signatures")
	}
}
