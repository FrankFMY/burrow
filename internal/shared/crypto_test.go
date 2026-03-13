package shared

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateRealityKeyPair(t *testing.T) {
	kp, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	privBytes, err := base64.RawURLEncoding.DecodeString(kp.PrivateKey)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("private key length: got %d, want 32", len(privBytes))
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(kp.PublicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("public key length: got %d, want 32", len(pubBytes))
	}

	kp2, _ := GenerateRealityKeyPair()
	if kp.PrivateKey == kp2.PrivateKey {
		t.Error("two generated key pairs should differ")
	}
}

func TestGenerateShortID(t *testing.T) {
	id, err := GenerateShortID()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(id) != 8 {
		t.Errorf("short id length: got %d, want 8 hex chars", len(id))
	}

	id2, _ := GenerateShortID()
	if id == id2 {
		t.Error("two generated short IDs should differ")
	}
}

func TestGeneratePassword(t *testing.T) {
	pass, err := GeneratePassword(16)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if pass == "" {
		t.Fatal("password should not be empty")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(pass)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded) != 16 {
		t.Errorf("decoded length: got %d, want 16", len(decoded))
	}

	pass2, _ := GeneratePassword(16)
	if pass == pass2 {
		t.Error("two generated passwords should differ")
	}
}

func TestGeneratePasswordDifferentLengths(t *testing.T) {
	p8, _ := GeneratePassword(8)
	p32, _ := GeneratePassword(32)

	d8, _ := base64.RawURLEncoding.DecodeString(p8)
	d32, _ := base64.RawURLEncoding.DecodeString(p32)

	if len(d8) != 8 {
		t.Errorf("8-byte password decoded length: got %d, want 8", len(d8))
	}
	if len(d32) != 32 {
		t.Errorf("32-byte password decoded length: got %d, want 32", len(d32))
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.crt")
	keyPath := filepath.Join(dir, "test.key")

	if err := GenerateSelfSignedCert(certPath, keyPath); err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatal("cert file should exist")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("key file should exist")
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("cert should be valid PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM type: got %q, want %q", block.Type, "CERTIFICATE")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if cert.Subject.CommonName != "burrow" {
		t.Errorf("CN: got %q, want %q", cert.Subject.CommonName, "burrow")
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		t.Fatal("key should be valid PEM")
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		t.Errorf("key PEM type: got %q, want %q", keyBlock.Type, "EC PRIVATE KEY")
	}
	_, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse EC private key: %v", err)
	}
}

func TestGenerateSelfSignedCertKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.key")
	certPath := filepath.Join(dir, "test.crt")

	if err := GenerateSelfSignedCert(certPath, keyPath); err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("key file permissions: got %o, want 0600", perm)
	}
}

func TestGenerateSS2022Key(t *testing.T) {
	key, err := GenerateSS2022Key()
	if err != nil {
		t.Fatalf("GenerateSS2022Key: %v", err)
	}
	if key == "" {
		t.Fatal("key should not be empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded key length: got %d, want 32", len(decoded))
	}

	key2, _ := GenerateSS2022Key()
	if key == key2 {
		t.Error("two generated SS2022 keys should differ")
	}
}
