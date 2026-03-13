package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FrankFMY/burrow/internal/shared"
)

func TestGetTUNMode(t *testing.T) {
	t.Run("nil defaults to true", func(t *testing.T) {
		cfg := &ClientConfig{}
		if !cfg.GetTUNMode() {
			t.Error("expected default TUN mode to be true")
		}
	})

	t.Run("explicit false", func(t *testing.T) {
		cfg := &ClientConfig{}
		cfg.SetTUNMode(false)
		if cfg.GetTUNMode() {
			t.Error("expected TUN mode to be false")
		}
	})

	t.Run("explicit true", func(t *testing.T) {
		cfg := &ClientConfig{}
		cfg.SetTUNMode(true)
		if !cfg.GetTUNMode() {
			t.Error("expected TUN mode to be true")
		}
	})
}

func TestAddServer(t *testing.T) {
	t.Run("add new server", func(t *testing.T) {
		cfg := &ClientConfig{}
		invite := shared.InviteData{
			Server: "1.2.3.4",
			Port:   443,
			Token:  "test-token",
			SNI:    "example.com",
			Name:   "Test Server",
		}
		cfg.AddServer(invite)

		if len(cfg.Servers) != 1 {
			t.Fatalf("expected 1 server, got %d", len(cfg.Servers))
		}
		if cfg.Servers[0].Name != "Test Server" {
			t.Errorf("expected name 'Test Server', got %q", cfg.Servers[0].Name)
		}
		if cfg.Servers[0].Invite.Server != "1.2.3.4" {
			t.Errorf("expected server '1.2.3.4', got %q", cfg.Servers[0].Invite.Server)
		}
	})

	t.Run("name defaults to server address", func(t *testing.T) {
		cfg := &ClientConfig{}
		invite := shared.InviteData{Server: "5.6.7.8", Token: "tok"}
		cfg.AddServer(invite)

		if cfg.Servers[0].Name != "5.6.7.8" {
			t.Errorf("expected name to be server address, got %q", cfg.Servers[0].Name)
		}
	})

	t.Run("updates existing server", func(t *testing.T) {
		cfg := &ClientConfig{}
		invite := shared.InviteData{Server: "1.2.3.4", Token: "tok1", Name: "Old"}
		cfg.AddServer(invite)

		invite.Name = "New"
		cfg.AddServer(invite)

		if len(cfg.Servers) != 1 {
			t.Fatalf("expected 1 server after update, got %d", len(cfg.Servers))
		}
		if cfg.Servers[0].Name != "New" {
			t.Errorf("expected updated name 'New', got %q", cfg.Servers[0].Name)
		}
	})

	t.Run("different token adds new server", func(t *testing.T) {
		cfg := &ClientConfig{}
		cfg.AddServer(shared.InviteData{Server: "1.2.3.4", Token: "tok1"})
		cfg.AddServer(shared.InviteData{Server: "1.2.3.4", Token: "tok2"})

		if len(cfg.Servers) != 2 {
			t.Fatalf("expected 2 servers, got %d", len(cfg.Servers))
		}
	})
}

func TestGetServer(t *testing.T) {
	cfg := &ClientConfig{}
	cfg.AddServer(shared.InviteData{Server: "1.2.3.4", Token: "t1", Name: "My Server"})

	t.Run("find by name", func(t *testing.T) {
		s := cfg.GetServer("My Server")
		if s == nil {
			t.Fatal("expected to find server by name")
		}
	})

	t.Run("find by address", func(t *testing.T) {
		s := cfg.GetServer("1.2.3.4")
		if s == nil {
			t.Fatal("expected to find server by address")
		}
	})

	t.Run("not found", func(t *testing.T) {
		s := cfg.GetServer("nonexistent")
		if s != nil {
			t.Fatal("expected nil for nonexistent server")
		}
	})
}

func TestGetLastServer(t *testing.T) {
	t.Run("returns first when no last set", func(t *testing.T) {
		cfg := &ClientConfig{}
		cfg.AddServer(shared.InviteData{Server: "1.1.1.1", Token: "t1", Name: "First"})
		cfg.AddServer(shared.InviteData{Server: "2.2.2.2", Token: "t2", Name: "Second"})

		s := cfg.GetLastServer()
		if s == nil || s.Name != "First" {
			t.Errorf("expected first server, got %v", s)
		}
	})

	t.Run("returns last used", func(t *testing.T) {
		cfg := &ClientConfig{Last: "2.2.2.2"}
		cfg.AddServer(shared.InviteData{Server: "1.1.1.1", Token: "t1", Name: "First"})
		cfg.AddServer(shared.InviteData{Server: "2.2.2.2", Token: "t2", Name: "Second"})

		s := cfg.GetLastServer()
		if s == nil || s.Name != "Second" {
			t.Errorf("expected Second server, got %v", s)
		}
	})

	t.Run("returns nil for empty config", func(t *testing.T) {
		cfg := &ClientConfig{}
		s := cfg.GetLastServer()
		if s != nil {
			t.Errorf("expected nil for empty config, got %v", s)
		}
	})
}

func TestSaveAndLoadClientConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := ConfigDir
	t.Cleanup(func() { ConfigDir = origConfigDir })

	ConfigDir = func() string { return tmpDir }

	cfg := &ClientConfig{
		Last:       "1.2.3.4",
		KillSwitch: true,
	}
	cfg.SetTUNMode(false)
	cfg.AddServer(shared.InviteData{
		Server: "1.2.3.4",
		Port:   443,
		Token:  "test-token",
		SNI:    "example.com",
		Name:   "Test",
	})

	if err := SaveClientConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "config.json")); err != nil {
		t.Fatalf("config file not created: %v", err)
	}

	loaded, err := LoadClientConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if loaded.Last != "1.2.3.4" {
		t.Errorf("expected last '1.2.3.4', got %q", loaded.Last)
	}
	if loaded.KillSwitch != true {
		t.Error("expected kill_switch true")
	}
	if loaded.GetTUNMode() != false {
		t.Error("expected tun_mode false")
	}
	if len(loaded.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(loaded.Servers))
	}
	if loaded.Servers[0].Name != "Test" {
		t.Errorf("expected server name 'Test', got %q", loaded.Servers[0].Name)
	}
}

func TestLoadClientConfig_NotExist(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := ConfigDir
	t.Cleanup(func() { ConfigDir = origConfigDir })

	ConfigDir = func() string { return filepath.Join(tmpDir, "nonexistent") }

	cfg, err := LoadClientConfig()
	if err != nil {
		t.Fatalf("expected no error for missing config, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("expected empty servers, got %d", len(cfg.Servers))
	}
}

func TestSplitTunnelConfigPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := ConfigDir
	origConfigPath := ConfigPath
	t.Cleanup(func() {
		ConfigDir = origConfigDir
		ConfigPath = origConfigPath
	})
	ConfigDir = func() string { return tmpDir }
	ConfigPath = func() string { return tmpDir + "/config.json" }

	cfg := &ClientConfig{
		SplitTunnel: &SplitTunnelConfig{
			Enabled:       true,
			BypassDomains: []string{"youtube.com", "google.com"},
			BypassIPs:     []string{"192.168.0.0/16", "10.0.0.0/8"},
		},
	}
	if err := SaveClientConfig(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadClientConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.SplitTunnel == nil {
		t.Fatal("expected split tunnel config")
	}
	if !loaded.SplitTunnel.Enabled {
		t.Error("expected split tunnel enabled")
	}
	if len(loaded.SplitTunnel.BypassDomains) != 2 {
		t.Errorf("expected 2 bypass domains, got %d", len(loaded.SplitTunnel.BypassDomains))
	}
	if len(loaded.SplitTunnel.BypassIPs) != 2 {
		t.Errorf("expected 2 bypass IPs, got %d", len(loaded.SplitTunnel.BypassIPs))
	}
}

func TestSplitTunnelNilByDefault(t *testing.T) {
	cfg := &ClientConfig{}
	if cfg.SplitTunnel != nil {
		t.Error("expected nil split tunnel by default")
	}
}

func TestLoadClientConfig_CorruptJSON(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := ConfigDir
	t.Cleanup(func() { ConfigDir = origConfigDir })

	ConfigDir = func() string { return tmpDir }

	os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte("{invalid"), 0600)

	_, err := LoadClientConfig()
	if err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
}

func TestClientValidate_EmptyConfig(t *testing.T) {
	cfg := &ClientConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty client config should be valid, got: %v", err)
	}
}

func TestClientValidate_ValidServers(t *testing.T) {
	cfg := &ClientConfig{
		Servers: []ServerEntry{
			{
				Name:    "Server 1",
				Invite:  shared.InviteData{Server: "1.2.3.4", Token: "tok1"},
				AddedAt: time.Now(),
			},
			{
				Name:    "Server 2",
				Invite:  shared.InviteData{Server: "5.6.7.8", Token: "tok2"},
				AddedAt: time.Now(),
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestClientValidate_EmptyServerName(t *testing.T) {
	cfg := &ClientConfig{
		Servers: []ServerEntry{
			{
				Name:   "",
				Invite: shared.InviteData{Server: "1.2.3.4", Token: "tok"},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty server name")
	}
	if !strings.Contains(err.Error(), "servers[0].name is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClientValidate_EmptyInviteServer(t *testing.T) {
	cfg := &ClientConfig{
		Servers: []ServerEntry{
			{
				Name:   "Test",
				Invite: shared.InviteData{Server: "", Token: "tok"},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty invite server")
	}
	if !strings.Contains(err.Error(), "servers[0].invite.server is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClientValidate_EmptyInviteToken(t *testing.T) {
	cfg := &ClientConfig{
		Servers: []ServerEntry{
			{
				Name:   "Test",
				Invite: shared.InviteData{Server: "1.2.3.4", Token: ""},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty invite token")
	}
	if !strings.Contains(err.Error(), "servers[0].invite.token is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClientValidate_MultipleServerErrors(t *testing.T) {
	cfg := &ClientConfig{
		Servers: []ServerEntry{
			{Name: "", Invite: shared.InviteData{Server: "", Token: ""}},
			{Name: "OK", Invite: shared.InviteData{Server: "1.2.3.4", Token: ""}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "servers[0].name") {
		t.Error("expected servers[0].name error")
	}
	if !strings.Contains(msg, "servers[0].invite.server") {
		t.Error("expected servers[0].invite.server error")
	}
	if !strings.Contains(msg, "servers[0].invite.token") {
		t.Error("expected servers[0].invite.token error")
	}
	if !strings.Contains(msg, "servers[1].invite.token") {
		t.Error("expected servers[1].invite.token error")
	}
}

func TestClientValidate_ValidBypassIPs(t *testing.T) {
	cfg := &ClientConfig{
		SplitTunnel: &SplitTunnelConfig{
			Enabled:   true,
			BypassIPs: []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error for valid CIDR, got: %v", err)
	}
}

func TestClientValidate_InvalidBypassIP(t *testing.T) {
	cfg := &ClientConfig{
		SplitTunnel: &SplitTunnelConfig{
			Enabled:   true,
			BypassIPs: []string{"192.168.0.0/16", "not-a-cidr", "10.0.0.0/8"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if !strings.Contains(err.Error(), "bypass_ips[1]") {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "not valid CIDR") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClientValidate_PlainIPNotCIDR(t *testing.T) {
	cfg := &ClientConfig{
		SplitTunnel: &SplitTunnelConfig{
			BypassIPs: []string{"192.168.1.1"},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for plain IP without CIDR mask")
	}
	if !strings.Contains(err.Error(), "not valid CIDR") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClientValidate_NilSplitTunnel(t *testing.T) {
	cfg := &ClientConfig{SplitTunnel: nil}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error for nil split tunnel, got: %v", err)
	}
}

func TestClientValidate_EmptyBypassIPs(t *testing.T) {
	cfg := &ClientConfig{
		SplitTunnel: &SplitTunnelConfig{
			BypassIPs: []string{},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error for empty bypass IPs, got: %v", err)
	}
}

func TestLoadClientConfig_ValidationFailure(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := ConfigDir
	origConfigPath := ConfigPath
	t.Cleanup(func() {
		ConfigDir = origConfigDir
		ConfigPath = origConfigPath
	})
	ConfigDir = func() string { return tmpDir }
	ConfigPath = func() string { return tmpDir + "/config.json" }

	invalid := &ClientConfig{
		Servers: []ServerEntry{
			{Name: "", Invite: shared.InviteData{Server: "", Token: ""}},
		},
	}
	data, _ := json.MarshalIndent(invalid, "", "  ")
	os.WriteFile(filepath.Join(tmpDir, "config.json"), data, 0600)

	_, err := LoadClientConfig()
	if err == nil {
		t.Fatal("LoadClientConfig should fail for invalid config")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestLoadClientConfig_ValidationPassesForValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := ConfigDir
	origConfigPath := ConfigPath
	t.Cleanup(func() {
		ConfigDir = origConfigDir
		ConfigPath = origConfigPath
	})
	ConfigDir = func() string { return tmpDir }
	ConfigPath = func() string { return tmpDir + "/config.json" }

	valid := &ClientConfig{
		Servers: []ServerEntry{
			{
				Name:    "Test",
				Invite:  shared.InviteData{Server: "1.2.3.4", Token: "tok"},
				AddedAt: time.Now(),
			},
		},
		SplitTunnel: &SplitTunnelConfig{
			BypassIPs: []string{"10.0.0.0/8"},
		},
	}
	data, _ := json.MarshalIndent(valid, "", "  ")
	os.WriteFile(filepath.Join(tmpDir, "config.json"), data, 0600)

	cfg, err := LoadClientConfig()
	if err != nil {
		t.Fatalf("expected valid config to load, got: %v", err)
	}
	if len(cfg.Servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(cfg.Servers))
	}
}

func TestGetTUNModeWithNilSplitTunnel(t *testing.T) {
	cfg := &ClientConfig{
		SplitTunnel: nil,
	}
	if !cfg.GetTUNMode() {
		t.Error("GetTUNMode should return true when TUNMode is nil, even with nil SplitTunnel")
	}
}

func TestConfigWithEmptyServersList(t *testing.T) {
	cfg := &ClientConfig{
		Servers: []ServerEntry{},
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(cfg.Servers))
	}
	s := cfg.GetServer("anything")
	if s != nil {
		t.Error("expected nil from GetServer on empty list")
	}
	s = cfg.GetLastServer()
	if s != nil {
		t.Error("expected nil from GetLastServer on empty list")
	}
}

func TestAddServerWithEmptyInviteFields(t *testing.T) {
	cfg := &ClientConfig{}
	invite := shared.InviteData{}
	cfg.AddServer(invite)

	if len(cfg.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(cfg.Servers))
	}
	if cfg.Servers[0].Name != "" {
		t.Errorf("name should be empty (server addr is empty), got %q", cfg.Servers[0].Name)
	}
	if cfg.Servers[0].Invite.Server != "" {
		t.Errorf("server should be empty, got %q", cfg.Servers[0].Invite.Server)
	}
}

func TestAddServerEmptyNameDefaultsToServerAddr(t *testing.T) {
	cfg := &ClientConfig{}
	invite := shared.InviteData{
		Server: "192.168.1.1",
		Port:   443,
		Token:  "tok",
	}
	cfg.AddServer(invite)

	if cfg.Servers[0].Name != "192.168.1.1" {
		t.Errorf("expected name to default to server addr %q, got %q", "192.168.1.1", cfg.Servers[0].Name)
	}
}

func TestSaveClientConfigToReadOnlyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	if err := os.MkdirAll(readOnlyDir, 0500); err != nil {
		t.Fatalf("create read-only dir: %v", err)
	}

	origConfigDir := ConfigDir
	origConfigPath := ConfigPath
	t.Cleanup(func() {
		ConfigDir = origConfigDir
		ConfigPath = origConfigPath
		os.Chmod(readOnlyDir, 0700)
	})

	nestedDir := filepath.Join(readOnlyDir, "subdir")
	ConfigDir = func() string { return nestedDir }
	ConfigPath = func() string { return filepath.Join(nestedDir, "config.json") }

	cfg := &ClientConfig{}
	err := SaveClientConfig(cfg)
	if err == nil {
		t.Fatal("expected error when saving to read-only directory")
	}
}

func TestSaveAndLoadClientConfigRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := ConfigDir
	origConfigPath := ConfigPath
	t.Cleanup(func() {
		ConfigDir = origConfigDir
		ConfigPath = origConfigPath
	})
	ConfigDir = func() string { return tmpDir }
	ConfigPath = func() string { return filepath.Join(tmpDir, "config.json") }

	cfg := &ClientConfig{
		KillSwitch:  true,
		AutoConnect: true,
		SplitTunnel: &SplitTunnelConfig{
			Enabled:       true,
			BypassDomains: []string{},
			BypassIPs:     []string{},
		},
	}
	cfg.SetTUNMode(false)

	if err := SaveClientConfig(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadClientConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.KillSwitch != true {
		t.Error("expected kill_switch true")
	}
	if loaded.AutoConnect != true {
		t.Error("expected auto_connect true")
	}
	if loaded.GetTUNMode() != false {
		t.Error("expected tun_mode false")
	}
	if loaded.SplitTunnel == nil {
		t.Fatal("expected split tunnel config")
	}
	if !loaded.SplitTunnel.Enabled {
		t.Error("expected split tunnel enabled")
	}
}
