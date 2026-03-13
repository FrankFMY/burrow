package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func TestGenerateToken(t *testing.T) {
	auth := NewAuth([]byte("test-secret-key"))

	token, err := auth.GenerateToken("admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}

	parsed, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		return []byte("test-secret-key"), nil
	})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}
	if claims.Subject != "admin" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "admin")
	}
	if claims.ExpiresAt == nil {
		t.Fatal("token should have expiration")
	}
	if claims.IssuedAt == nil {
		t.Fatal("token should have issued_at")
	}
}

func TestGenerateTokenDifferentSubjects(t *testing.T) {
	auth := NewAuth([]byte("test-secret"))

	t1, _ := auth.GenerateToken("user1", time.Hour)
	t2, _ := auth.GenerateToken("user2", time.Hour)
	if t1 == t2 {
		t.Error("tokens for different subjects should differ")
	}
}

func TestValidateTokenValid(t *testing.T) {
	auth := NewAuth([]byte("test-secret-key"))

	token, err := auth.GenerateToken("admin", time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	claims, err := auth.ValidateToken(token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Subject != "admin" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "admin")
	}
}

func TestValidateTokenExpired(t *testing.T) {
	auth := NewAuth([]byte("test-secret-key"))

	token, err := auth.GenerateToken("admin", -time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	_, err = auth.ValidateToken(token)
	if err == nil {
		t.Fatal("expired token should fail validation")
	}
}

func TestValidateTokenInvalid(t *testing.T) {
	auth := NewAuth([]byte("test-secret-key"))

	_, err := auth.ValidateToken("not-a-valid-token")
	if err == nil {
		t.Fatal("invalid token should fail validation")
	}
}

func TestValidateTokenTampered(t *testing.T) {
	auth := NewAuth([]byte("test-secret-key"))

	token, err := auth.GenerateToken("admin", time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	tampered := token + "x"
	_, err = auth.ValidateToken(tampered)
	if err == nil {
		t.Fatal("tampered token should fail validation")
	}
}

func TestValidateTokenWrongSecret(t *testing.T) {
	auth1 := NewAuth([]byte("secret-1"))
	auth2 := NewAuth([]byte("secret-2"))

	token, err := auth1.GenerateToken("admin", time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	_, err = auth2.ValidateToken(token)
	if err == nil {
		t.Fatal("token signed with different secret should fail validation")
	}
}

func TestHashPasswordAndCheck(t *testing.T) {
	hash, err := HashPassword("my-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	if hash == "my-password" {
		t.Fatal("hash should not equal plaintext")
	}

	if !CheckPassword(hash, "my-password") {
		t.Error("correct password should match")
	}
}

func TestBcryptCostConstant(t *testing.T) {
	if BcryptCost < 12 {
		t.Errorf("BcryptCost should be at least 12, got %d", BcryptCost)
	}

	hash, err := HashPassword("cost-test")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("get cost: %v", err)
	}
	if cost != BcryptCost {
		t.Errorf("bcrypt cost: got %d, want %d", cost, BcryptCost)
	}
}

func TestCheckPasswordWrong(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if CheckPassword(hash, "wrong-password") {
		t.Error("wrong password should not match")
	}
}

func TestHashPasswordDifferentHashes(t *testing.T) {
	h1, _ := HashPassword("same-password")
	h2, _ := HashPassword("same-password")
	if h1 == h2 {
		t.Error("bcrypt hashes should differ due to salt")
	}
}

func TestMiddlewareValidToken(t *testing.T) {
	auth := NewAuth([]byte("test-secret"))
	token, _ := auth.GenerateToken("admin", time.Hour)

	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(claimsKey).(*jwt.RegisteredClaims)
		if !ok {
			t.Error("claims not found in context")
			return
		}
		if claims.Subject != "admin" {
			t.Errorf("subject: got %q, want %q", claims.Subject, "admin")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareMissingToken(t *testing.T) {
	auth := NewAuth([]byte("test-secret"))

	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareExpiredToken(t *testing.T) {
	auth := NewAuth([]byte("test-secret"))
	token, _ := auth.GenerateToken("admin", -time.Hour)

	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareInvalidToken(t *testing.T) {
	auth := NewAuth([]byte("test-secret"))

	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-string")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareInvalidFormat(t *testing.T) {
	auth := NewAuth([]byte("test-secret"))

	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Basic some-credentials")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
