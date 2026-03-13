package client

import (
	"os"
	"path/filepath"
	"testing"

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
