package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/FrankFMY/burrow/internal/server/store"
	"github.com/FrankFMY/burrow/internal/shared"
)

func setupTestAPI(t *testing.T) (*API, *Auth, *store.SQLiteStore) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.NewSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	passwordHash, err := HashPassword("admin-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	auth := NewAuth([]byte("test-jwt-secret"))
	cfg := &ServerConfig{
		ListenPort:        443,
		APIPort:           8080,
		CamouflageSNI:     "www.microsoft.com",
		RealityPublicKey:  "test-public-key",
		RealityPrivateKey: "test-private-key",
		ShortID:           "abcd1234",
		AdminPasswordHash: passwordHash,
		JWTSecret:         "test-jwt-secret",
		ServerAddr:        "10.0.0.1",
	}

	api := NewAPI(db, auth, cfg, "10.0.0.1")
	return api, auth, db
}

func authToken(t *testing.T, auth *Auth) string {
	t.Helper()
	token, err := auth.GenerateToken("admin", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	return token
}

func doRequest(t *testing.T, router http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
	}
}

func TestLoginCorrectPassword(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "POST", "/api/auth/login", map[string]string{"password": "admin-password"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp map[string]string
	decodeJSON(t, rec, &resp)
	if resp["token"] == "" {
		t.Fatal("response should contain token")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "POST", "/api/auth/login", map[string]string{"password": "wrong-password"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestConnectValidToken(t *testing.T) {
	api, _, db := setupTestAPI(t)
	router := api.Router()

	client := &store.Client{
		ID:        "client-1",
		Name:      "Test Client",
		Token:     "connect-token-123",
		CreatedAt: time.Now().UTC(),
	}
	if err := db.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	rec := doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "connect-token-123"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	if resp["client_id"] != "client-1" {
		t.Errorf("client_id: got %v, want %q", resp["client_id"], "client-1")
	}
	protocols, ok := resp["protocols"].([]any)
	if !ok || len(protocols) == 0 {
		t.Fatal("response should contain protocols")
	}
}

func TestConnectInvalidToken(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "nonexistent-token"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestConnectRevokedClient(t *testing.T) {
	api, _, db := setupTestAPI(t)
	router := api.Router()

	client := &store.Client{
		ID:        "revoked-client",
		Name:      "Revoked",
		Token:     "revoked-token",
		CreatedAt: time.Now().UTC(),
	}
	db.CreateClient(context.Background(), client)
	db.RevokeClient(context.Background(), "revoked-client")

	rec := doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "revoked-token"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestListClientsRequiresAuth(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "GET", "/api/clients", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestListClientsAuthenticated(t *testing.T) {
	api, auth, db := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	db.CreateClient(context.Background(), &store.Client{
		ID: "c1", Name: "Client 1", Token: "t1", CreatedAt: time.Now().UTC(),
	})
	db.CreateClient(context.Background(), &store.Client{
		ID: "c2", Name: "Client 2", Token: "t2", CreatedAt: time.Now().UTC(),
	})

	rec := doRequest(t, router, "GET", "/api/clients", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}

	var clients []store.Client
	decodeJSON(t, rec, &clients)
	if len(clients) != 2 {
		t.Errorf("clients count: got %d, want 2", len(clients))
	}
}

func TestRevokeClientRequiresAuth(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "DELETE", "/api/clients/some-id", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRevokeClientAuthenticated(t *testing.T) {
	api, auth, db := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	db.CreateClient(context.Background(), &store.Client{
		ID: "del-1", Name: "Delete Me", Token: "dt1", CreatedAt: time.Now().UTC(),
	})

	rec := doRequest(t, router, "DELETE", "/api/clients/del-1", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp map[string]string
	decodeJSON(t, rec, &resp)
	if resp["status"] != "revoked" {
		t.Errorf("status: got %q, want %q", resp["status"], "revoked")
	}
}

func TestRevokeClientNotFound(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "DELETE", "/api/clients/nonexistent", nil, token)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestListInvitesRequiresAuth(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "GET", "/api/invites", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestListInvitesAuthenticated(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "GET", "/api/invites", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}

	var clients []store.Client
	decodeJSON(t, rec, &clients)
	if clients == nil {
		t.Error("response should be an array, not nil")
	}
}

func TestCreateInviteRequiresAuth(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "POST", "/api/invites", map[string]string{"name": "test"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestCreateInviteAuthenticated(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "POST", "/api/invites", map[string]string{"name": "New Client"}, token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	if resp["invite"] == nil {
		t.Error("response should contain invite link")
	}
	if resp["client"] == nil {
		t.Error("response should contain client data")
	}
}

func TestCreateInviteMissingName(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "POST", "/api/invites", map[string]string{}, token)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateInviteWithExpiry(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "POST", "/api/invites", map[string]string{
		"name":       "Expiring Client",
		"expires_in": "24h",
	}, token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

func TestRevokeInviteRequiresAuth(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "DELETE", "/api/invites/some-id", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRevokeInviteAuthenticated(t *testing.T) {
	api, auth, db := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	db.CreateClient(context.Background(), &store.Client{
		ID: "inv-1", Name: "Invite 1", Token: "it1", CreatedAt: time.Now().UTC(),
	})

	rec := doRequest(t, router, "DELETE", "/api/invites/inv-1", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp map[string]string
	decodeJSON(t, rec, &resp)
	if resp["status"] != "revoked" {
		t.Errorf("status: got %q, want %q", resp["status"], "revoked")
	}
}

func TestRevokeInviteNotFound(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "DELETE", "/api/invites/nonexistent", nil, token)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGetStatsRequiresAuth(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "GET", "/api/stats", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestGetStatsAuthenticated(t *testing.T) {
	api, auth, db := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	db.CreateClient(context.Background(), &store.Client{
		ID: "s1", Name: "Stats Client", Token: "st1", CreatedAt: time.Now().UTC(),
	})

	rec := doRequest(t, router, "GET", "/api/stats", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}

	var stats store.Stats
	decodeJSON(t, rec, &stats)
	if stats.TotalClients != 1 {
		t.Errorf("total_clients: got %d, want 1", stats.TotalClients)
	}
}

func TestGetConfigRequiresAuth(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "GET", "/api/config", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestGetConfigAuthenticated(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "GET", "/api/config", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	if resp["listen_port"] == nil {
		t.Error("response should contain listen_port")
	}
	if resp["server_addr"] != "10.0.0.1" {
		t.Errorf("server_addr: got %v, want %q", resp["server_addr"], "10.0.0.1")
	}
}

func TestHealthEndpoint(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "GET", "/health", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	if resp["status"] != "ok" {
		t.Errorf("health status: got %v, want %q", resp["status"], "ok")
	}
}

func TestCreateInviteWithCDNWebSocket(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	api.config.CDNWebSocket = &CDNWebSocketConfig{
		Enabled: true,
		Port:    8080,
		Path:    "/ws",
		Host:    "cdn.example.com",
	}
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "POST", "/api/invites", map[string]string{"name": "CDN Client"}, token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	inviteLink, ok := resp["invite"].(string)
	if !ok || inviteLink == "" {
		t.Fatal("response should contain invite link")
	}

	invite, err := shared.DecodeInvite(inviteLink)
	if err != nil {
		t.Fatalf("decode invite: %v", err)
	}
	if invite.CDNHost != "cdn.example.com" {
		t.Errorf("cdn_host: got %q, want %q", invite.CDNHost, "cdn.example.com")
	}
	if invite.CDNPort != 443 {
		t.Errorf("cdn_port: got %d, want 443", invite.CDNPort)
	}
	if invite.CDNPath != "/ws" {
		t.Errorf("cdn_path: got %q, want %q", invite.CDNPath, "/ws")
	}
}

func TestConnectWithCDNWebSocket(t *testing.T) {
	api, _, db := setupTestAPI(t)
	api.config.CDNWebSocket = &CDNWebSocketConfig{
		Enabled: true,
		Port:    8080,
		Path:    "/ws",
		Host:    "cdn.example.com",
	}
	router := api.Router()

	client := &store.Client{
		ID:        "cdn-client",
		Name:      "CDN Client",
		Token:     "cdn-token-123",
		CreatedAt: time.Now().UTC(),
	}
	if err := db.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	rec := doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "cdn-token-123"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	protocols, ok := resp["protocols"].([]any)
	if !ok {
		t.Fatal("response should contain protocols")
	}

	foundCDN := false
	for _, p := range protocols {
		proto, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if proto["type"] == "vless-ws" {
			foundCDN = true
			if proto["cdn_host"] != "cdn.example.com" {
				t.Errorf("cdn_host: got %v, want %q", proto["cdn_host"], "cdn.example.com")
			}
			if proto["cdn_path"] != "/ws" {
				t.Errorf("cdn_path: got %v, want %q", proto["cdn_path"], "/ws")
			}
		}
	}
	if !foundCDN {
		t.Error("protocols should include vless-ws when CDN is enabled")
	}
}

func TestCreateInviteWithoutCDNWebSocket(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "POST", "/api/invites", map[string]string{"name": "No CDN Client"}, token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	inviteLink := resp["invite"].(string)

	invite, err := shared.DecodeInvite(inviteLink)
	if err != nil {
		t.Fatalf("decode invite: %v", err)
	}
	if invite.CDNHost != "" {
		t.Errorf("cdn_host should be empty when CDN not enabled, got %q", invite.CDNHost)
	}
}

func TestLoginInvalidBody(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRotateKeysRequiresAuth(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "POST", "/api/rotate-keys", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRotateKeysNoConfigPath(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "POST", "/api/rotate-keys", nil, token)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}

	var resp map[string]string
	decodeJSON(t, rec, &resp)
	if resp["error"] != "config path not configured" {
		t.Errorf("error: got %q, want %q", resp["error"], "config path not configured")
	}
}

func TestRotateKeysSuccess(t *testing.T) {
	api, auth, _ := setupTestAPI(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := SaveConfig(cfgPath, api.config); err != nil {
		t.Fatalf("save config: %v", err)
	}
	api.SetConfigPath(cfgPath)

	router := api.Router()
	token := authToken(t, auth)

	oldPubKey := api.config.RealityPublicKey
	oldShortID := api.config.ShortID
	oldJWTSecret := api.config.JWTSecret

	rec := doRequest(t, router, "POST", "/api/rotate-keys", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	if resp["status"] != "rotated" {
		t.Errorf("status: got %v, want %q", resp["status"], "rotated")
	}
	if resp["public_key"] == nil || resp["public_key"] == "" {
		t.Error("response should contain new public_key")
	}
	if resp["short_id"] == nil || resp["short_id"] == "" {
		t.Error("response should contain new short_id")
	}

	if api.config.RealityPublicKey == oldPubKey {
		t.Error("public key should have changed")
	}
	if api.config.ShortID == oldShortID {
		t.Error("short_id should have changed")
	}
	if api.config.JWTSecret == oldJWTSecret {
		t.Error("JWT secret should have changed")
	}

	if len(api.config.LegacyPublicKeys) != 1 {
		t.Fatalf("legacy_public_keys: got %d, want 1", len(api.config.LegacyPublicKeys))
	}
	if api.config.LegacyPublicKeys[0] != oldPubKey {
		t.Errorf("legacy_public_keys[0]: got %q, want %q", api.config.LegacyPublicKeys[0], oldPubKey)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.RealityPublicKey != api.config.RealityPublicKey {
		t.Error("saved config public key should match in-memory config")
	}
	if len(loaded.LegacyPublicKeys) != 1 {
		t.Errorf("saved legacy_public_keys: got %d, want 1", len(loaded.LegacyPublicKeys))
	}
}

func TestRotateKeysInvalidatesOldTokens(t *testing.T) {
	api, auth, _ := setupTestAPI(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := SaveConfig(cfgPath, api.config); err != nil {
		t.Fatalf("save config: %v", err)
	}
	api.SetConfigPath(cfgPath)

	router := api.Router()
	oldToken := authToken(t, auth)

	rec := doRequest(t, router, "POST", "/api/rotate-keys", nil, oldToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate status: got %d, want %d", rec.Code, http.StatusOK)
	}

	rec = doRequest(t, router, "GET", "/api/config", nil, oldToken)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("old token should be invalid after rotation, got status %d", rec.Code)
	}
}

func TestRotateKeysMultipleTimes(t *testing.T) {
	api, auth, _ := setupTestAPI(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := SaveConfig(cfgPath, api.config); err != nil {
		t.Fatalf("save config: %v", err)
	}
	api.SetConfigPath(cfgPath)

	router := api.Router()
	firstPubKey := api.config.RealityPublicKey

	token := authToken(t, auth)
	rec := doRequest(t, router, "POST", "/api/rotate-keys", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("first rotation status: got %d, want %d", rec.Code, http.StatusOK)
	}

	secondPubKey := api.config.RealityPublicKey

	newAuth := NewAuth([]byte(api.config.JWTSecret))
	token2 := authToken(t, newAuth)
	rec = doRequest(t, router, "POST", "/api/rotate-keys", nil, token2)
	if rec.Code != http.StatusOK {
		t.Fatalf("second rotation status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if len(api.config.LegacyPublicKeys) != 2 {
		t.Fatalf("legacy_public_keys: got %d, want 2", len(api.config.LegacyPublicKeys))
	}
	if api.config.LegacyPublicKeys[0] != firstPubKey {
		t.Errorf("legacy[0]: got %q, want %q", api.config.LegacyPublicKeys[0], firstPubKey)
	}
	if api.config.LegacyPublicKeys[1] != secondPubKey {
		t.Errorf("legacy[1]: got %q, want %q", api.config.LegacyPublicKeys[1], secondPubKey)
	}
}

func TestBandwidthLimitEnforced(t *testing.T) {
	api, _, db := setupTestAPI(t)
	router := api.Router()

	client := &store.Client{
		ID:             "bw-limited",
		Name:           "BW Limited",
		Token:          "bw-token-limited",
		CreatedAt:      time.Now().UTC(),
		BandwidthLimit: 1000,
	}
	if err := db.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	if err := db.RecordTraffic(context.Background(), "bw-token-limited", 500, 0); err != nil {
		t.Fatalf("record traffic 1: %v", err)
	}
	if err := db.RecordTraffic(context.Background(), "bw-token-limited", 0, 500); err != nil {
		t.Fatalf("record traffic 2: %v", err)
	}

	rec := doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "bw-token-limited"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	var resp map[string]string
	decodeJSON(t, rec, &resp)
	if resp["error"] != "bandwidth limit exceeded" {
		t.Errorf("error: got %q, want %q", resp["error"], "bandwidth limit exceeded")
	}
}

func TestBandwidthLimitNotExceeded(t *testing.T) {
	api, _, db := setupTestAPI(t)
	router := api.Router()

	client := &store.Client{
		ID:             "bw-ok",
		Name:           "BW OK",
		Token:          "bw-token-ok",
		CreatedAt:      time.Now().UTC(),
		BandwidthLimit: 2000,
	}
	if err := db.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("create client: %v", err)
	}

	if err := db.RecordTraffic(context.Background(), "bw-token-ok", 300, 200); err != nil {
		t.Fatalf("record traffic: %v", err)
	}

	rec := doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "bw-token-ok"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	if _, ok := resp["protocols"]; !ok {
		t.Error("response should contain protocols")
	}
}

func TestLogoutBlocksToken(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "POST", "/api/auth/logout", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status: got %d, want %d", rec.Code, http.StatusOK)
	}

	rec = doRequest(t, router, "GET", "/api/clients", nil, token)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("after logout status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestGetClientFound(t *testing.T) {
	api, auth, db := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	db.CreateClient(context.Background(), &store.Client{
		ID: "get-1", Name: "Get Me", Token: "get-token-1", CreatedAt: time.Now().UTC(),
	})

	rec := doRequest(t, router, "GET", "/api/clients/get-1", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var client store.Client
	decodeJSON(t, rec, &client)
	if client.ID != "get-1" {
		t.Errorf("id: got %q, want %q", client.ID, "get-1")
	}
	if client.Name != "Get Me" {
		t.Errorf("name: got %q, want %q", client.Name, "Get Me")
	}
}

func TestGetClientNotFound(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "GET", "/api/clients/nonexistent", nil, token)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHealthDetailed(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "GET", "/api/health/detailed", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	if _, ok := resp["uptime_sec"]; !ok {
		t.Error("response should contain uptime_sec")
	}
	if _, ok := resp["memory"]; !ok {
		t.Error("response should contain memory")
	}
	if _, ok := resp["goroutines"]; !ok {
		t.Error("response should contain goroutines")
	}
	if _, ok := resp["db_size_bytes"]; !ok {
		t.Error("response should contain db_size_bytes")
	}
}

func TestGetLogs(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "GET", "/api/logs", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var entries []any
	decodeJSON(t, rec, &entries)
	if entries == nil {
		t.Error("response should be an array, not nil")
	}
}

func TestGetLogsNegativeLimit(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "GET", "/api/logs?limit=-5", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var entries []any
	decodeJSON(t, rec, &entries)
	if entries == nil {
		t.Error("response should be an array, not nil")
	}
}

func TestGetLogsCappedLimit(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "GET", "/api/logs?limit=999", nil, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var entries []any
	decodeJSON(t, rec, &entries)
	if entries == nil {
		t.Error("response should be an array, not nil")
	}
}

func TestLoginRateLimit(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	for i := 0; i < 5; i++ {
		rec := doRequest(t, router, "POST", "/api/auth/login", map[string]string{"password": "wrong"}, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want %d", i+1, rec.Code, http.StatusUnauthorized)
		}
	}

	rec := doRequest(t, router, "POST", "/api/auth/login", map[string]string{"password": "wrong"}, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("6th attempt: got %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}

func TestCreateInviteNegativeBandwidth(t *testing.T) {
	api, auth, _ := setupTestAPI(t)
	router := api.Router()
	token := authToken(t, auth)

	rec := doRequest(t, router, "POST", "/api/invites", map[string]any{
		"name":            "Bad BW",
		"bandwidth_limit": -1,
	}, token)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestConnectExpiredClient(t *testing.T) {
	api, _, db := setupTestAPI(t)
	router := api.Router()

	expired := time.Now().Add(-time.Hour)
	client := &store.Client{
		ID:        "expired-client",
		Name:      "Expired",
		Token:     "expired-token",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: &expired,
	}
	db.CreateClient(context.Background(), client)

	rec := doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "expired-token"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestConnectTracksSession(t *testing.T) {
	api, _, db := setupTestAPI(t)
	router := api.Router()

	db.CreateClient(context.Background(), &store.Client{
		ID: "track-1", Name: "Track Me", Token: "track-token", CreatedAt: time.Now().UTC(),
	})

	rec := doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "track-token"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if api.tracker.ActiveSessions() != 1 {
		t.Errorf("active sessions: got %d, want 1", api.tracker.ActiveSessions())
	}

	client, err := db.GetClientByToken(context.Background(), "track-token")
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if client.LastConnectedAt == nil {
		t.Error("last_connected_at should be set after connect")
	}
}

func TestDisconnectEndpoint(t *testing.T) {
	api, _, db := setupTestAPI(t)
	router := api.Router()

	db.CreateClient(context.Background(), &store.Client{
		ID: "disc-1", Name: "Disconnect Me", Token: "disc-token", CreatedAt: time.Now().UTC(),
	})

	doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "disc-token"}, "")

	rec := doRequest(t, router, "POST", "/api/disconnect", map[string]any{
		"token":      "disc-token",
		"bytes_up":   1024,
		"bytes_down": 2048,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if api.tracker.ActiveSessions() != 0 {
		t.Errorf("active sessions: got %d, want 0", api.tracker.ActiveSessions())
	}

	client, err := db.GetClientByToken(context.Background(), "disc-token")
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if client.BytesUp != 1024 {
		t.Errorf("bytes_up: got %d, want 1024", client.BytesUp)
	}
	if client.BytesDown != 2048 {
		t.Errorf("bytes_down: got %d, want 2048", client.BytesDown)
	}
}

func TestDisconnectMissingToken(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "POST", "/api/disconnect", map[string]any{
		"bytes_up":   100,
		"bytes_down": 200,
	}, "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHeartbeatEndpoint(t *testing.T) {
	api, _, db := setupTestAPI(t)
	router := api.Router()

	db.CreateClient(context.Background(), &store.Client{
		ID: "hb-1", Name: "Heartbeat Me", Token: "hb-token", CreatedAt: time.Now().UTC(),
	})

	doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "hb-token"}, "")

	rec := doRequest(t, router, "POST", "/api/heartbeat", map[string]any{
		"token":      "hb-token",
		"bytes_up":   500,
		"bytes_down": 1000,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if api.tracker.ActiveSessions() != 1 {
		t.Errorf("active sessions: got %d, want 1", api.tracker.ActiveSessions())
	}

	client, err := db.GetClientByToken(context.Background(), "hb-token")
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if client.BytesUp != 500 {
		t.Errorf("bytes_up: got %d, want 500", client.BytesUp)
	}
	if client.BytesDown != 1000 {
		t.Errorf("bytes_down: got %d, want 1000", client.BytesDown)
	}
}

func TestHeartbeatMissingToken(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	router := api.Router()

	rec := doRequest(t, router, "POST", "/api/heartbeat", map[string]any{
		"bytes_up":   100,
		"bytes_down": 200,
	}, "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestConnectThenHeartbeatThenDisconnect(t *testing.T) {
	api, _, db := setupTestAPI(t)
	router := api.Router()

	db.CreateClient(context.Background(), &store.Client{
		ID: "full-1", Name: "Full Flow", Token: "full-token", CreatedAt: time.Now().UTC(),
	})

	rec := doRequest(t, router, "POST", "/api/connect", map[string]string{"token": "full-token"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("connect: got %d", rec.Code)
	}

	rec = doRequest(t, router, "POST", "/api/heartbeat", map[string]any{
		"token": "full-token", "bytes_up": 100, "bytes_down": 200,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat 1: got %d", rec.Code)
	}

	rec = doRequest(t, router, "POST", "/api/heartbeat", map[string]any{
		"token": "full-token", "bytes_up": 150, "bytes_down": 300,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("heartbeat 2: got %d", rec.Code)
	}

	rec = doRequest(t, router, "POST", "/api/disconnect", map[string]any{
		"token": "full-token", "bytes_up": 50, "bytes_down": 100,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("disconnect: got %d", rec.Code)
	}

	if api.tracker.ActiveSessions() != 0 {
		t.Errorf("active sessions: got %d, want 0", api.tracker.ActiveSessions())
	}

	client, err := db.GetClientByToken(context.Background(), "full-token")
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	expectedUp := int64(100 + 150 + 50)
	expectedDown := int64(200 + 300 + 100)
	if client.BytesUp != expectedUp {
		t.Errorf("bytes_up: got %d, want %d", client.BytesUp, expectedUp)
	}
	if client.BytesDown != expectedDown {
		t.Errorf("bytes_down: got %d, want %d", client.BytesDown, expectedDown)
	}
}
