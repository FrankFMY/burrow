package shared

import (
	"encoding/base64"
	"strings"
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

func TestDecodeInviteEmptyString(t *testing.T) {
	_, err := DecodeInvite("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestDecodeInviteMalformedBase64(t *testing.T) {
	inputs := []string{
		InviteScheme + "====",
		InviteScheme + "not@valid#base64!",
		InviteScheme + " ",
		InviteScheme + "\t\n",
	}
	for _, input := range inputs {
		_, err := DecodeInvite(input)
		if err == nil {
			t.Errorf("expected error for malformed base64 input %q", input)
		}
	}
}

func TestDecodeInviteValidBase64InvalidJSON(t *testing.T) {
	raw := base64.RawURLEncoding.EncodeToString([]byte("not json at all"))
	_, err := DecodeInvite(InviteScheme + raw)
	if err == nil {
		t.Fatal("expected error for valid base64 but invalid JSON")
	}
}

func TestDecodeInviteValidBase64PartialJSON(t *testing.T) {
	raw := base64.RawURLEncoding.EncodeToString([]byte(`{"s":"10.0.0.1"`))
	_, err := DecodeInvite(InviteScheme + raw)
	if err == nil {
		t.Fatal("expected error for truncated JSON")
	}
}

func TestDecodeInviteAllOptionalFieldsEmpty(t *testing.T) {
	data := InviteData{
		Server:    "10.0.0.1",
		Port:      443,
		Token:     "tok",
		SNI:       "sni.example.com",
		PublicKey: "pk",
		ShortID:   "1234",
	}
	link, err := EncodeInvite(data)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeInvite(link)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Name != "" {
		t.Errorf("name should be empty, got %q", decoded.Name)
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
	if decoded.Sig != "" {
		t.Errorf("sig should be empty, got %q", decoded.Sig)
	}
}

func TestEncodeDecodeInviteUnicodeName(t *testing.T) {
	names := []string{
		"Телефон Артёма",
		"iPhone 日本語",
		"서버-한국어",
		"emoji \U0001F680\U0001F30D",
	}
	for _, name := range names {
		data := InviteData{
			Server:    "10.0.0.1",
			Port:      443,
			Token:     "tok",
			SNI:       "sni.example.com",
			PublicKey: "pk",
			ShortID:   "1234",
			Name:      name,
		}
		link, err := EncodeInvite(data)
		if err != nil {
			t.Fatalf("encode with name %q: %v", name, err)
		}
		decoded, err := DecodeInvite(link)
		if err != nil {
			t.Fatalf("decode with name %q: %v", name, err)
		}
		if decoded.Name != name {
			t.Errorf("name roundtrip: got %q, want %q", decoded.Name, name)
		}
	}
}

func TestEncodeDecodeInviteMaxLengthStrings(t *testing.T) {
	longStr := strings.Repeat("a", 10000)
	data := InviteData{
		Server:    longStr,
		Port:      65535,
		Token:     longStr,
		SNI:       longStr,
		PublicKey: longStr,
		ShortID:   longStr,
		Name:      longStr,
		CDNHost:   longStr,
		CDNPort:   65535,
		CDNPath:   longStr,
	}
	link, err := EncodeInvite(data)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeInvite(link)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Server != longStr {
		t.Errorf("server length: got %d, want %d", len(decoded.Server), len(longStr))
	}
	if decoded.Name != longStr {
		t.Errorf("name length: got %d, want %d", len(decoded.Name), len(longStr))
	}
	if decoded.Port != 65535 {
		t.Errorf("port: got %d, want 65535", decoded.Port)
	}
}

func TestDoubleEncodeDecodeRoundTrip(t *testing.T) {
	original := InviteData{
		Server:    "10.0.0.1",
		Port:      443,
		Token:     "double-trip-token",
		SNI:       "www.example.com",
		PublicKey: "pk",
		ShortID:   "abcd",
		Name:      "Round Trip",
		CDNHost:   "cdn.example.com",
		CDNPort:   8080,
		CDNPath:   "/ws",
	}

	link1, err := EncodeInvite(original)
	if err != nil {
		t.Fatalf("first encode: %v", err)
	}
	decoded1, err := DecodeInvite(link1)
	if err != nil {
		t.Fatalf("first decode: %v", err)
	}

	link2, err := EncodeInvite(decoded1)
	if err != nil {
		t.Fatalf("second encode: %v", err)
	}
	decoded2, err := DecodeInvite(link2)
	if err != nil {
		t.Fatalf("second decode: %v", err)
	}

	if decoded2.Server != original.Server {
		t.Errorf("server: got %q, want %q", decoded2.Server, original.Server)
	}
	if decoded2.Port != original.Port {
		t.Errorf("port: got %d, want %d", decoded2.Port, original.Port)
	}
	if decoded2.Token != original.Token {
		t.Errorf("token: got %q, want %q", decoded2.Token, original.Token)
	}
	if decoded2.Name != original.Name {
		t.Errorf("name: got %q, want %q", decoded2.Name, original.Name)
	}
	if decoded2.CDNHost != original.CDNHost {
		t.Errorf("cdn_host: got %q, want %q", decoded2.CDNHost, original.CDNHost)
	}
	if link1 != link2 {
		t.Error("double encode should produce identical links")
	}
}

func TestDecodeInviteSchemeOnly(t *testing.T) {
	_, err := DecodeInvite(InviteScheme)
	if err == nil {
		t.Fatal("expected error for scheme-only input")
	}
}

func TestDecodeInviteValidBase64EmptyJSON(t *testing.T) {
	raw := base64.RawURLEncoding.EncodeToString([]byte("{}"))
	decoded, err := DecodeInvite(InviteScheme + raw)
	if err != nil {
		t.Fatalf("decode empty JSON object: %v", err)
	}
	if decoded.Server != "" {
		t.Errorf("server should be empty, got %q", decoded.Server)
	}
	if decoded.Port != 0 {
		t.Errorf("port should be 0, got %d", decoded.Port)
	}
}

func FuzzDecodeInvite(f *testing.F) {
	f.Add("burrow://connect/eyJzIjoiMTAuMC4wLjEiLCJwIjo0NDMsImsiOiJ0b2siLCJzbmkiOiJleGFtcGxlLmNvbSIsInBrIjoicGsiLCJzaWQiOiIxMjM0In0")
	f.Add("")
	f.Add("burrow://connect/")
	f.Add("burrow://connect/!!!invalid!!!")
	f.Add("https://example.com")
	f.Add("burrow://connect/e30")

	f.Fuzz(func(t *testing.T, input string) {
		decoded, err := DecodeInvite(input)
		if err != nil {
			return
		}
		reencoded, err := EncodeInvite(decoded)
		if err != nil {
			t.Fatalf("re-encode of successfully decoded invite failed: %v", err)
		}
		decoded2, err := DecodeInvite(reencoded)
		if err != nil {
			t.Fatalf("decode of re-encoded invite failed: %v", err)
		}
		if decoded.Server != decoded2.Server || decoded.Port != decoded2.Port || decoded.Token != decoded2.Token {
			t.Error("round-trip mismatch after re-encode")
		}
	})
}
