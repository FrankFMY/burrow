package client

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	tmpDir := t.TempDir()
	origConfigDir := ConfigDir
	origConfigPath := ConfigPath
	t.Cleanup(func() {
		ConfigDir = origConfigDir
		ConfigPath = origConfigPath
	})
	ConfigDir = func() string { return tmpDir }
	ConfigPath = func() string { return tmpDir + "/config.json" }

	cfg := &ClientConfig{}
	if err := SaveClientConfig(cfg); err != nil {
		t.Fatalf("save initial config: %v", err)
	}
	return &Daemon{config: cfg}
}

func TestHandleStatus_NotConnected(t *testing.T) {
	d := newTestDaemon(t)
	req := httptest.NewRequest("GET", "/api/status", nil)
	w := httptest.NewRecorder()

	d.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["running"] != false {
		t.Error("expected running=false")
	}
}

func TestHandleConnect_NoServers(t *testing.T) {
	d := newTestDaemon(t)
	body := `{"tun_mode": false, "kill_switch": false}`
	req := httptest.NewRequest("POST", "/api/connect", strings.NewReader(body))
	w := httptest.NewRecorder()

	d.handleConnect(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "no server found" {
		t.Errorf("expected 'no server found', got %q", resp["error"])
	}
}

func TestHandleConnect_InvalidRequest(t *testing.T) {
	d := newTestDaemon(t)
	req := httptest.NewRequest("POST", "/api/connect", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	d.handleConnect(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleDisconnect_NotConnected(t *testing.T) {
	d := newTestDaemon(t)
	req := httptest.NewRequest("POST", "/api/disconnect", nil)
	w := httptest.NewRecorder()

	d.handleDisconnect(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "not connected" {
		t.Errorf("expected 'not connected', got %q", resp["status"])
	}
}

func TestHandleListServers_Empty(t *testing.T) {
	d := newTestDaemon(t)
	req := httptest.NewRequest("GET", "/api/servers", nil)
	w := httptest.NewRecorder()

	d.handleListServers(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var servers []map[string]any
	json.NewDecoder(w.Body).Decode(&servers)
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestHandleAddServer(t *testing.T) {
	d := newTestDaemon(t)

	invite := `{"s":"1.2.3.4","p":443,"k":"token","sni":"example.com","pk":"pk","sid":"sid","n":"Test"}`
	encoded := "burrow://connect/" + encodeBase64(invite)
	body := `{"invite":"` + encoded + `"}`

	req := httptest.NewRequest("POST", "/api/servers", strings.NewReader(body))
	w := httptest.NewRecorder()

	d.handleAddServer(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["name"] != "Test" {
		t.Errorf("expected name 'Test', got %v", resp["name"])
	}
}

func TestHandleAddServer_InvalidInvite(t *testing.T) {
	d := newTestDaemon(t)
	body := `{"invite":"not-a-valid-invite"}`
	req := httptest.NewRequest("POST", "/api/servers", strings.NewReader(body))
	w := httptest.NewRecorder()

	d.handleAddServer(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleRemoveServer(t *testing.T) {
	d := newTestDaemon(t)

	invite := `{"s":"1.2.3.4","p":443,"k":"token","sni":"example.com","pk":"pk","sid":"sid","n":"Test"}`
	encoded := "burrow://connect/" + encodeBase64(invite)
	addBody := `{"invite":"` + encoded + `"}`
	addReq := httptest.NewRequest("POST", "/api/servers", strings.NewReader(addBody))
	addW := httptest.NewRecorder()
	d.handleAddServer(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("add server failed: %d %s", addW.Code, addW.Body.String())
	}

	req := httptest.NewRequest("DELETE", "/api/servers/Test", nil)
	req.SetPathValue("name", "Test")
	w := httptest.NewRecorder()
	d.handleRemoveServer(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleRemoveServer_NotFound(t *testing.T) {
	d := newTestDaemon(t)
	req := httptest.NewRequest("DELETE", "/api/servers/nonexistent", nil)
	req.SetPathValue("name", "nonexistent")
	w := httptest.NewRecorder()

	d.handleRemoveServer(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleVersion(t *testing.T) {
	d := newTestDaemon(t)
	req := httptest.NewRequest("GET", "/api/version", nil)
	w := httptest.NewRecorder()

	d.handleVersion(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if _, ok := resp["version"]; !ok {
		t.Error("expected version field")
	}
	if _, ok := resp["config_dir"]; !ok {
		t.Error("expected config_dir field")
	}
}

func TestHandleGetPreferences(t *testing.T) {
	d := newTestDaemon(t)
	req := httptest.NewRequest("GET", "/api/preferences", nil)
	w := httptest.NewRecorder()

	d.handleGetPreferences(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["tun_mode"] != true {
		t.Errorf("expected tun_mode=true (default), got %v", resp["tun_mode"])
	}
}

func TestHandleSetPreferences(t *testing.T) {
	d := newTestDaemon(t)
	body := `{"tun_mode": false, "kill_switch": true, "auto_connect": true}`
	req := httptest.NewRequest("PUT", "/api/preferences", strings.NewReader(body))
	w := httptest.NewRecorder()

	d.handleSetPreferences(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["tun_mode"] != false {
		t.Errorf("expected tun_mode=false, got %v", resp["tun_mode"])
	}
	if resp["kill_switch"] != true {
		t.Errorf("expected kill_switch=true, got %v", resp["kill_switch"])
	}
	if resp["auto_connect"] != true {
		t.Errorf("expected auto_connect=true, got %v", resp["auto_connect"])
	}

	getReq := httptest.NewRequest("GET", "/api/preferences", nil)
	getW := httptest.NewRecorder()
	d.handleGetPreferences(getW, getReq)

	var loaded map[string]any
	json.NewDecoder(getW.Body).Decode(&loaded)
	if loaded["tun_mode"] != false {
		t.Error("preferences not persisted")
	}
}

func TestHandleSetPreferences_Invalid(t *testing.T) {
	d := newTestDaemon(t)
	req := httptest.NewRequest("PUT", "/api/preferences", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	d.handleSetPreferences(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandlePingServer_NotFound(t *testing.T) {
	d := newTestDaemon(t)
	req := httptest.NewRequest("GET", "/api/servers/nonexistent/ping", nil)
	req.SetPathValue("name", "nonexistent")
	w := httptest.NewRecorder()

	d.handlePingServer(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestReconnectDelay(t *testing.T) {
	tests := []struct {
		attempt int
		want    string
	}{
		{1, "1s"},
		{2, "2s"},
		{3, "4s"},
		{4, "8s"},
		{5, "16s"},
		{6, "30s"},
		{7, "30s"},
	}
	for _, tt := range tests {
		d := reconnectDelay(tt.attempt)
		if d.String() != tt.want {
			t.Errorf("reconnectDelay(%d) = %s, want %s", tt.attempt, d, tt.want)
		}
	}
}

func TestFriendlyError(t *testing.T) {
	tests := []struct {
		err      string
		wantCode string
	}{
		{"permission denied", "PERMISSION_DENIED"},
		{"operation not permitted", "PERMISSION_DENIED"},
		{"context deadline exceeded", "TIMEOUT"},
		{"i/o timeout", "TIMEOUT"},
		{"connection refused", "SERVER_UNREACHABLE"},
		{"address already in use", "PORT_IN_USE"},
		{"no such host", "DNS_ERROR"},
		{"certificate verify failed", "TLS_ERROR"},
		{"tls handshake error", "TLS_ERROR"},
		{"something unexpected", "UNKNOWN"},
	}

	for _, tt := range tests {
		code, _ := friendlyError(errors.New(tt.err))
		if code != tt.wantCode {
			t.Errorf("friendlyError(%q) code = %q, want %q", tt.err, code, tt.wantCode)
		}
	}
}

func TestFriendlyError_Truncation(t *testing.T) {
	longErr := strings.Repeat("x", 200)
	_, msg := friendlyError(errors.New(longErr))
	if len(msg) > 200 {
		t.Errorf("expected truncated message, got length %d", len(msg))
	}
	if !strings.HasSuffix(msg, "...") {
		t.Error("expected truncated message to end with ...")
	}
}

func TestCORSWrap(t *testing.T) {
	handler := corsWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("allowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "tauri://localhost")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "tauri://localhost" {
			t.Error("expected CORS header for tauri origin")
		}
	})

	t.Run("disallowed origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://evil.com")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("expected no CORS header for disallowed origin")
		}
	})

	t.Run("preflight", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://localhost:5173")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("expected 204, got %d", w.Code)
		}
	})
}

func TestWriteJSONResponse(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONResponse(w, http.StatusCreated, map[string]string{"key": "value"})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["key"] != "value" {
		t.Errorf("expected value, got %q", resp["key"])
	}
}

func encodeBase64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
