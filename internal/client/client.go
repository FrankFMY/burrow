package client

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/FrankFMY/burrow/internal/shared"
)

type SplitTunnelConfig struct {
	Enabled       bool     `json:"enabled"`
	BypassDomains []string `json:"bypass_domains,omitempty"`
	BypassIPs     []string `json:"bypass_ips,omitempty"`
}

type ClientConfig struct {
	Servers     []ServerEntry      `json:"servers"`
	Last        string             `json:"last,omitempty"`
	TUNMode     *bool              `json:"tun_mode,omitempty"`
	KillSwitch  bool               `json:"kill_switch,omitempty"`
	AutoConnect bool               `json:"auto_connect,omitempty"`
	SplitTunnel *SplitTunnelConfig `json:"split_tunnel,omitempty"`
}

func (cfg *ClientConfig) GetTUNMode() bool {
	if cfg.TUNMode == nil {
		return true
	}
	return *cfg.TUNMode
}

func (cfg *ClientConfig) SetTUNMode(v bool) {
	cfg.TUNMode = &v
}

type ServerEntry struct {
	Name     string            `json:"name"`
	Invite   shared.InviteData `json:"invite"`
	Protocol string            `json:"protocol,omitempty"`
	AddedAt  time.Time         `json:"added_at"`
}

var ConfigDir = func() string {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "burrow")
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "burrow")
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "burrow")
	}
}

var ConfigPath = func() string {
	return filepath.Join(ConfigDir(), "config.json")
}

func (cfg *ClientConfig) Validate() error {
	var errs []string

	for i, s := range cfg.Servers {
		prefix := fmt.Sprintf("servers[%d]", i)
		if s.Name == "" {
			errs = append(errs, fmt.Sprintf("%s.name is required", prefix))
		}
		if s.Invite.Server == "" {
			errs = append(errs, fmt.Sprintf("%s.invite.server is required", prefix))
		}
		if s.Invite.Token == "" {
			errs = append(errs, fmt.Sprintf("%s.invite.token is required", prefix))
		}
	}

	if cfg.SplitTunnel != nil {
		for i, cidr := range cfg.SplitTunnel.BypassIPs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				errs = append(errs, fmt.Sprintf("split_tunnel.bypass_ips[%d] %q is not valid CIDR notation", i, cidr))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("client config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func LoadClientConfig() (*ClientConfig, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &ClientConfig{}, nil
		}
		return nil, err
	}
	var cfg ClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func SaveClientConfig(cfg *ClientConfig) error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	path := ConfigPath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (cfg *ClientConfig) AddServer(invite shared.InviteData) {
	name := invite.Name
	if name == "" {
		name = invite.Server
	}

	for i, s := range cfg.Servers {
		if s.Invite.Server == invite.Server && s.Invite.Token == invite.Token {
			cfg.Servers[i].Invite = invite
			cfg.Servers[i].Name = name
			return
		}
	}

	cfg.Servers = append(cfg.Servers, ServerEntry{
		Name:    name,
		Invite:  invite,
		AddedAt: time.Now().UTC(),
	})
}

func (cfg *ClientConfig) GetServer(nameOrAddr string) *ServerEntry {
	for i := range cfg.Servers {
		if cfg.Servers[i].Name == nameOrAddr || cfg.Servers[i].Invite.Server == nameOrAddr {
			return &cfg.Servers[i]
		}
	}
	return nil
}

func (cfg *ClientConfig) GetLastServer() *ServerEntry {
	if cfg.Last == "" && len(cfg.Servers) > 0 {
		return &cfg.Servers[0]
	}
	return cfg.GetServer(cfg.Last)
}

type ConnectResponse struct {
	ClientID  string            `json:"client_id"`
	Name      string            `json:"name"`
	Protocols []json.RawMessage `json:"protocols"`
}

func FetchConfig(invite shared.InviteData) (*ConnectResponse, error) {
	apiURL := fmt.Sprintf("http://%s:%d/api/connect", invite.Server, 8080)

	bodyData, err := json.Marshal(map[string]string{"token": invite.Token})
	if err != nil {
		return nil, fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(bodyData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("api connect failed, using invite data directly", "error", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned %d", resp.StatusCode)
	}

	var result ConnectResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
