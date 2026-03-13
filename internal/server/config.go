package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FrankFMY/burrow/internal/shared"
	"github.com/google/uuid"
)

const (
	DefaultPort          = 443
	DefaultAPIPort       = 8080
	DefaultCamouflageSNI = "www.microsoft.com"
	ConfigFileName       = "burrow-server.json"
	DatabaseFileName     = "burrow.db"
)

type ServerConfig struct {
	ListenPort        uint16 `json:"listen_port"`
	APIPort           uint16 `json:"api_port"`
	CamouflageSNI     string `json:"camouflage_sni"`
	RealityPrivateKey string `json:"reality_private_key"`
	RealityPublicKey  string `json:"reality_public_key"`
	ShortID           string `json:"short_id"`
	AdminPasswordHash string `json:"admin_password_hash"`
	JWTSecret         string `json:"jwt_secret"`
	ServerAddr        string `json:"server_addr"`
	DataDir           string `json:"data_dir"`
	Users             []User `json:"users"`

	Hysteria2    *Hysteria2Config       `json:"hysteria2,omitempty"`
	SS2022       *Shadowsocks2022Config `json:"ss2022,omitempty"`
	WireGuard    *WireGuardConfig       `json:"wireguard,omitempty"`
	CDNWebSocket *CDNWebSocketConfig    `json:"cdn_websocket,omitempty"`
}

type Hysteria2Config struct {
	Enabled  bool   `json:"enabled"`
	Port     uint16 `json:"port"`
	Password string `json:"password"`
	CertPath string `json:"cert_path,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
}

type Shadowsocks2022Config struct {
	Enabled bool   `json:"enabled"`
	Port    uint16 `json:"port"`
	Method  string `json:"method"`
	Key     string `json:"key"`
}

type WireGuardConfig struct {
	Enabled    bool   `json:"enabled"`
	Port       uint16 `json:"port"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type RelayConfig struct {
	ListenPort      uint16 `json:"listen_port"`
	UpstreamServer  string `json:"upstream_server"`
	UpstreamPort    uint16 `json:"upstream_port"`
	UpstreamSNI     string `json:"upstream_sni"`
	UpstreamPubKey  string `json:"upstream_pub_key"`
	UpstreamShortID string `json:"upstream_short_id"`
}

type CDNWebSocketConfig struct {
	Enabled bool   `json:"enabled"`
	Port    uint16 `json:"port"`
	Path    string `json:"path"`
	Host    string `json:"host"`
}

type User struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

func DefaultConfigPath() string {
	return filepath.Join("/etc/burrow", ConfigFileName)
}

func (c *ServerConfig) DatabasePath() string {
	dir := c.DataDir
	if dir == "" {
		dir = "/var/lib/burrow"
	}
	return filepath.Join(dir, DatabaseFileName)
}

func LoadConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

func SaveConfig(path string, cfg *ServerConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func AddUser(cfg *ServerConfig, name string) (User, error) {
	u := User{
		Name: name,
		UUID: uuid.New().String(),
	}
	cfg.Users = append(cfg.Users, u)
	return u, nil
}

func GenerateConfig(port, apiPort uint16, sni, password, serverAddr, dataDir string) (*ServerConfig, error) {
	keys, err := shared.GenerateRealityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate keys: %w", err)
	}
	shortID, err := shared.GenerateShortID()
	if err != nil {
		return nil, fmt.Errorf("generate short id: %w", err)
	}

	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	jwtSecret, err := shared.GeneratePassword(32)
	if err != nil {
		return nil, fmt.Errorf("generate jwt secret: %w", err)
	}

	if dataDir == "" {
		dataDir = "/var/lib/burrow"
	}

	hy2pass, err := shared.GeneratePassword(16)
	if err != nil {
		return nil, fmt.Errorf("generate hysteria2 password: %w", err)
	}

	ssKey, err := shared.GenerateSS2022Key()
	if err != nil {
		return nil, fmt.Errorf("generate ss2022 key: %w", err)
	}

	wgKeys, err := shared.GenerateRealityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate wireguard keys: %w", err)
	}

	certPath := filepath.Join(dataDir, "tls.crt")
	keyPath := filepath.Join(dataDir, "tls.key")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := shared.GenerateSelfSignedCert(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("generate tls cert: %w", err)
	}

	return &ServerConfig{
		ListenPort:        port,
		APIPort:           apiPort,
		CamouflageSNI:     sni,
		RealityPrivateKey: keys.PrivateKey,
		RealityPublicKey:  keys.PublicKey,
		ShortID:           shortID,
		AdminPasswordHash: passwordHash,
		JWTSecret:         jwtSecret,
		ServerAddr:        serverAddr,
		DataDir:           dataDir,
		Hysteria2: &Hysteria2Config{
			Enabled:  true,
			Port:     8443,
			Password: hy2pass,
			CertPath: certPath,
			KeyPath:  keyPath,
		},
		SS2022: &Shadowsocks2022Config{
			Enabled: true,
			Port:    8388,
			Method:  "2022-blake3-aes-256-gcm",
			Key:     ssKey,
		},
		WireGuard: &WireGuardConfig{
			Enabled:    false,
			Port:       51820,
			PrivateKey: wgKeys.PrivateKey,
			PublicKey:  wgKeys.PublicKey,
		},
		CDNWebSocket: &CDNWebSocketConfig{
			Enabled: false,
			Port:    8080,
			Path:    "/ws",
		},
	}, nil
}
