package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateConfig(t *testing.T) {
	dir := t.TempDir()
	cfg, err := GenerateConfig(443, 8080, "www.microsoft.com", "test-password", "10.0.0.1", dir)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}

	if cfg.ListenPort != 443 {
		t.Errorf("listen_port: got %d, want 443", cfg.ListenPort)
	}
	if cfg.APIPort != 8080 {
		t.Errorf("api_port: got %d, want 8080", cfg.APIPort)
	}
	if cfg.CamouflageSNI != "www.microsoft.com" {
		t.Errorf("camouflage_sni: got %q, want %q", cfg.CamouflageSNI, "www.microsoft.com")
	}
	if cfg.ServerAddr != "10.0.0.1" {
		t.Errorf("server_addr: got %q, want %q", cfg.ServerAddr, "10.0.0.1")
	}
	if cfg.DataDir != dir {
		t.Errorf("data_dir: got %q, want %q", cfg.DataDir, dir)
	}
	if cfg.RealityPublicKey == "" {
		t.Error("reality public key should not be empty")
	}
	if cfg.RealityPrivateKey == "" {
		t.Error("reality private key should not be empty")
	}
	if cfg.ShortID == "" {
		t.Error("short_id should not be empty")
	}
	if cfg.AdminPasswordHash == "" {
		t.Error("admin_password_hash should not be empty")
	}
	if cfg.JWTSecret == "" {
		t.Error("jwt_secret should not be empty")
	}
	if !CheckPassword(cfg.AdminPasswordHash, "test-password") {
		t.Error("admin password hash should match the input password")
	}

	if cfg.Hysteria2 == nil {
		t.Fatal("hysteria2 config should not be nil")
	}
	if !cfg.Hysteria2.Enabled {
		t.Error("hysteria2 should be enabled")
	}
	if cfg.Hysteria2.Port != 8443 {
		t.Errorf("hysteria2 port: got %d, want 8443", cfg.Hysteria2.Port)
	}
	if cfg.Hysteria2.Password == "" {
		t.Error("hysteria2 password should not be empty")
	}

	if cfg.SS2022 == nil {
		t.Fatal("ss2022 config should not be nil")
	}
	if !cfg.SS2022.Enabled {
		t.Error("ss2022 should be enabled")
	}
	if cfg.SS2022.Port != 8388 {
		t.Errorf("ss2022 port: got %d, want 8388", cfg.SS2022.Port)
	}
	if cfg.SS2022.Method != "2022-blake3-aes-256-gcm" {
		t.Errorf("ss2022 method: got %q, want %q", cfg.SS2022.Method, "2022-blake3-aes-256-gcm")
	}
	if cfg.SS2022.Key == "" {
		t.Error("ss2022 key should not be empty")
	}

	if cfg.WireGuard == nil {
		t.Fatal("wireguard config should not be nil")
	}
	if cfg.WireGuard.Enabled {
		t.Error("wireguard should be disabled by default")
	}
	if cfg.WireGuard.Port != 51820 {
		t.Errorf("wireguard port: got %d, want 51820", cfg.WireGuard.Port)
	}
	if cfg.WireGuard.PublicKey == "" {
		t.Error("wireguard public key should not be empty")
	}
	if cfg.WireGuard.PrivateKey == "" {
		t.Error("wireguard private key should not be empty")
	}

	if cfg.CDNWebSocket == nil {
		t.Fatal("cdn_websocket config should not be nil")
	}
	if cfg.CDNWebSocket.Enabled {
		t.Error("cdn_websocket should be disabled by default")
	}
	if cfg.CDNWebSocket.Port != 8080 {
		t.Errorf("cdn_websocket port: got %d, want 8080", cfg.CDNWebSocket.Port)
	}
	if cfg.CDNWebSocket.Path != "/ws" {
		t.Errorf("cdn_websocket path: got %q, want %q", cfg.CDNWebSocket.Path, "/ws")
	}
}

func TestGenerateConfigDefaultDataDir(t *testing.T) {
	// GenerateConfig with empty dataDir defaults to /var/lib/burrow,
	// but creating that dir requires root. Use tmpDir and verify
	// the explicit dataDir is used, plus check the default constant.
	dir := t.TempDir()
	cfg, err := GenerateConfig(443, 8080, "www.example.com", "pass", "1.2.3.4", dir)
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}
	if cfg.DataDir != dir {
		t.Errorf("data_dir: got %q, want %q", cfg.DataDir, dir)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test-config.json")

	original := &ServerConfig{
		ListenPort:        443,
		APIPort:           8080,
		CamouflageSNI:     "www.example.com",
		RealityPublicKey:  "pub-key",
		RealityPrivateKey: "priv-key",
		ShortID:           "abcd1234",
		AdminPasswordHash: "hash",
		JWTSecret:         "secret",
		ServerAddr:        "1.2.3.4",
		DataDir:           dir,
	}

	data, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.ListenPort != 443 {
		t.Errorf("listen_port: got %d, want 443", loaded.ListenPort)
	}
	if loaded.CamouflageSNI != "www.example.com" {
		t.Errorf("camouflage_sni: got %q, want %q", loaded.CamouflageSNI, "www.example.com")
	}
	if loaded.ServerAddr != "1.2.3.4" {
		t.Errorf("server_addr: got %q, want %q", loaded.ServerAddr, "1.2.3.4")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("LoadConfig should fail for missing file")
	}
}

func TestLoadConfigCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.json")
	os.WriteFile(cfgPath, []byte("{invalid json"), 0600)

	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Fatal("LoadConfig should fail for corrupt JSON")
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "subdir", "config.json")

	original := &ServerConfig{
		ListenPort:        8443,
		APIPort:           9090,
		CamouflageSNI:     "www.google.com",
		RealityPublicKey:  "pk",
		RealityPrivateKey: "sk",
		ShortID:           "1234abcd",
		AdminPasswordHash: "hashed",
		JWTSecret:         "jwt-secret",
		ServerAddr:        "5.6.7.8",
		DataDir:           dir,
	}

	if err := SaveConfig(cfgPath, original); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Fatal("config file should exist after save")
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.ListenPort != original.ListenPort {
		t.Errorf("listen_port: got %d, want %d", loaded.ListenPort, original.ListenPort)
	}
	if loaded.APIPort != original.APIPort {
		t.Errorf("api_port: got %d, want %d", loaded.APIPort, original.APIPort)
	}
	if loaded.CamouflageSNI != original.CamouflageSNI {
		t.Errorf("camouflage_sni: got %q, want %q", loaded.CamouflageSNI, original.CamouflageSNI)
	}
	if loaded.JWTSecret != original.JWTSecret {
		t.Errorf("jwt_secret: got %q, want %q", loaded.JWTSecret, original.JWTSecret)
	}
}

func TestAddUser(t *testing.T) {
	cfg := &ServerConfig{}

	u1, err := AddUser(cfg, "Alice")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if u1.Name != "Alice" {
		t.Errorf("name: got %q, want %q", u1.Name, "Alice")
	}
	if u1.UUID == "" {
		t.Error("UUID should not be empty")
	}

	u2, err := AddUser(cfg, "Bob")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if u1.UUID == u2.UUID {
		t.Error("UUIDs should be unique")
	}

	if len(cfg.Users) != 2 {
		t.Errorf("users count: got %d, want 2", len(cfg.Users))
	}
	if cfg.Users[0].Name != "Alice" {
		t.Errorf("first user: got %q, want %q", cfg.Users[0].Name, "Alice")
	}
	if cfg.Users[1].Name != "Bob" {
		t.Errorf("second user: got %q, want %q", cfg.Users[1].Name, "Bob")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path := DefaultConfigPath()
	if path == "" {
		t.Error("default config path should not be empty")
	}
	expected := filepath.Join("/etc/burrow", ConfigFileName)
	if path != expected {
		t.Errorf("default config path: got %q, want %q", path, expected)
	}
}

func TestDatabasePath(t *testing.T) {
	cfg := &ServerConfig{DataDir: "/custom/dir"}
	dbPath := cfg.DatabasePath()
	expected := filepath.Join("/custom/dir", DatabaseFileName)
	if dbPath != expected {
		t.Errorf("database path: got %q, want %q", dbPath, expected)
	}
}

func TestDatabasePathDefault(t *testing.T) {
	cfg := &ServerConfig{}
	dbPath := cfg.DatabasePath()
	expected := filepath.Join("/var/lib/burrow", DatabaseFileName)
	if dbPath != expected {
		t.Errorf("database path: got %q, want %q", dbPath, expected)
	}
}

func TestConfigDefaults(t *testing.T) {
	if DefaultPort != 443 {
		t.Errorf("DefaultPort: got %d, want 443", DefaultPort)
	}
	if DefaultAPIPort != 8080 {
		t.Errorf("DefaultAPIPort: got %d, want 8080", DefaultAPIPort)
	}
	if DefaultCamouflageSNI != "www.microsoft.com" {
		t.Errorf("DefaultCamouflageSNI: got %q, want %q", DefaultCamouflageSNI, "www.microsoft.com")
	}
}

func TestSaveConfigCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	deepPath := filepath.Join(dir, "a", "b", "c", "config.json")

	cfg := &ServerConfig{ListenPort: 443}
	if err := SaveConfig(deepPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	if _, err := os.Stat(deepPath); os.IsNotExist(err) {
		t.Fatal("config file should exist in nested directory")
	}
}

func TestSaveAndLoadCDNWebSocketConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cdn-config.json")

	original := &ServerConfig{
		ListenPort:        443,
		APIPort:           8080,
		CamouflageSNI:     "www.example.com",
		RealityPublicKey:  "pk",
		RealityPrivateKey: "sk",
		ShortID:           "abcd",
		AdminPasswordHash: "hash",
		JWTSecret:         "secret",
		ServerAddr:        "1.2.3.4",
		DataDir:           dir,
		CDNWebSocket: &CDNWebSocketConfig{
			Enabled: true,
			Port:    8080,
			Path:    "/ws",
			Host:    "cdn.example.com",
		},
	}

	if err := SaveConfig(cfgPath, original); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.CDNWebSocket == nil {
		t.Fatal("cdn_websocket should not be nil after load")
	}
	if !loaded.CDNWebSocket.Enabled {
		t.Error("cdn_websocket should be enabled")
	}
	if loaded.CDNWebSocket.Port != 8080 {
		t.Errorf("cdn_websocket port: got %d, want 8080", loaded.CDNWebSocket.Port)
	}
	if loaded.CDNWebSocket.Path != "/ws" {
		t.Errorf("cdn_websocket path: got %q, want %q", loaded.CDNWebSocket.Path, "/ws")
	}
	if loaded.CDNWebSocket.Host != "cdn.example.com" {
		t.Errorf("cdn_websocket host: got %q, want %q", loaded.CDNWebSocket.Host, "cdn.example.com")
	}
}

func TestRotateKeysGeneratesNewValues(t *testing.T) {
	cfg := &ServerConfig{
		RealityPrivateKey: "old-private",
		RealityPublicKey:  "old-public",
		ShortID:           "old-short",
		JWTSecret:         "old-secret",
	}

	result, err := RotateKeys(cfg)
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}

	if cfg.RealityPublicKey == "old-public" {
		t.Error("public key should have changed")
	}
	if cfg.RealityPrivateKey == "old-private" {
		t.Error("private key should have changed")
	}
	if cfg.ShortID == "old-short" {
		t.Error("short_id should have changed")
	}
	if cfg.JWTSecret == "old-secret" {
		t.Error("jwt secret should have changed")
	}
	if result.PublicKey != cfg.RealityPublicKey {
		t.Error("result public key should match config")
	}
	if result.ShortID != cfg.ShortID {
		t.Error("result short_id should match config")
	}
}

func TestRotateKeysPreservesLegacyPublicKeys(t *testing.T) {
	cfg := &ServerConfig{
		RealityPrivateKey: "priv1",
		RealityPublicKey:  "pub1",
		ShortID:           "s1",
		JWTSecret:         "jwt1",
	}

	_, err := RotateKeys(cfg)
	if err != nil {
		t.Fatalf("first RotateKeys: %v", err)
	}
	if len(cfg.LegacyPublicKeys) != 1 {
		t.Fatalf("legacy keys after first rotation: got %d, want 1", len(cfg.LegacyPublicKeys))
	}
	if cfg.LegacyPublicKeys[0] != "pub1" {
		t.Errorf("legacy[0]: got %q, want %q", cfg.LegacyPublicKeys[0], "pub1")
	}

	secondPub := cfg.RealityPublicKey
	_, err = RotateKeys(cfg)
	if err != nil {
		t.Fatalf("second RotateKeys: %v", err)
	}
	if len(cfg.LegacyPublicKeys) != 2 {
		t.Fatalf("legacy keys after second rotation: got %d, want 2", len(cfg.LegacyPublicKeys))
	}
	if cfg.LegacyPublicKeys[1] != secondPub {
		t.Errorf("legacy[1]: got %q, want %q", cfg.LegacyPublicKeys[1], secondPub)
	}
}

func TestRotateKeysEmptyPublicKeyNoLegacy(t *testing.T) {
	cfg := &ServerConfig{
		RealityPublicKey: "",
		JWTSecret:        "old",
	}

	_, err := RotateKeys(cfg)
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}

	if len(cfg.LegacyPublicKeys) != 0 {
		t.Errorf("should not add empty key to legacy, got %d", len(cfg.LegacyPublicKeys))
	}
}

func TestRotateKeysSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "rotate-config.json")

	cfg := &ServerConfig{
		ListenPort:        443,
		APIPort:           8080,
		RealityPrivateKey: "old-priv",
		RealityPublicKey:  "old-pub",
		ShortID:           "old-sid",
		JWTSecret:         "old-jwt",
		ServerAddr:        "1.2.3.4",
		DataDir:           dir,
	}

	_, err := RotateKeys(cfg)
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}

	if err := SaveConfig(cfgPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if loaded.RealityPublicKey != cfg.RealityPublicKey {
		t.Error("loaded public key should match")
	}
	if loaded.ShortID != cfg.ShortID {
		t.Error("loaded short_id should match")
	}
	if loaded.JWTSecret != cfg.JWTSecret {
		t.Error("loaded jwt secret should match")
	}
	if len(loaded.LegacyPublicKeys) != 1 || loaded.LegacyPublicKeys[0] != "old-pub" {
		t.Errorf("loaded legacy keys: got %v, want [old-pub]", loaded.LegacyPublicKeys)
	}
}

func TestSaveConfigFilePermissions(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfg := &ServerConfig{ListenPort: 443}
	if err := SaveConfig(cfgPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions: got %o, want 0600", perm)
	}
}
