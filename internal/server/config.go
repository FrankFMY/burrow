package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	ListenPort        uint16   `json:"listen_port"`
	APIPort           uint16   `json:"api_port"`
	CamouflageSNI     string   `json:"camouflage_sni"`
	RealityPrivateKey string   `json:"reality_private_key"`
	RealityPublicKey  string   `json:"reality_public_key"`
	ShortID           string   `json:"short_id"`
	AdminPasswordHash string   `json:"admin_password_hash"`
	JWTSecret         string   `json:"jwt_secret"`
	ServerAddr        string   `json:"server_addr"`
	DataDir           string   `json:"data_dir"`
	Users             []User   `json:"users"`
	LegacyPublicKeys  []string `json:"legacy_public_keys,omitempty"`

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

func validatePort(name string, port uint16) error {
	if port == 0 {
		return fmt.Errorf("%s 0 is invalid (must be 1-65535)", name)
	}
	return nil
}

func (c *ServerConfig) Validate() error {
	var errs []string

	if err := validatePort("listen_port", c.ListenPort); err != nil {
		errs = append(errs, err.Error())
	}
	if err := validatePort("api_port", c.APIPort); err != nil {
		errs = append(errs, err.Error())
	}

	if c.CamouflageSNI == "" {
		errs = append(errs, "camouflage_sni is required")
	}

	if c.RealityPrivateKey == "" {
		errs = append(errs, "reality_private_key is required")
	} else if len(c.RealityPrivateKey) != 43 && len(c.RealityPrivateKey) != 44 {
		errs = append(errs, fmt.Sprintf("reality_private_key length %d is invalid (must be 43-44 chars for Curve25519 base64)", len(c.RealityPrivateKey)))
	}

	if c.RealityPublicKey == "" {
		errs = append(errs, "reality_public_key is required")
	} else if len(c.RealityPublicKey) != 43 && len(c.RealityPublicKey) != 44 {
		errs = append(errs, fmt.Sprintf("reality_public_key length %d is invalid (must be 43-44 chars for Curve25519 base64)", len(c.RealityPublicKey)))
	}

	if c.ShortID == "" {
		errs = append(errs, "short_id is required")
	} else {
		if len(c.ShortID) != 8 && len(c.ShortID) != 16 {
			errs = append(errs, fmt.Sprintf("short_id length %d is invalid (must be 8 or 16 hex chars)", len(c.ShortID)))
		} else if _, err := hex.DecodeString(c.ShortID); err != nil {
			errs = append(errs, fmt.Sprintf("short_id %q is not valid hex", c.ShortID))
		}
	}

	if c.AdminPasswordHash == "" {
		errs = append(errs, "admin_password_hash is required")
	}
	if c.JWTSecret == "" {
		errs = append(errs, "jwt_secret is required")
	}
	if c.ServerAddr == "" {
		errs = append(errs, "server_addr is required")
	}

	if c.Hysteria2 != nil && c.Hysteria2.Enabled {
		if err := validatePort("hysteria2.port", c.Hysteria2.Port); err != nil {
			errs = append(errs, err.Error())
		}
		if c.Hysteria2.Password == "" {
			errs = append(errs, "hysteria2.password is required when hysteria2 is enabled")
		}
		if c.Hysteria2.CertPath == "" {
			errs = append(errs, "hysteria2.cert_path is required when hysteria2 is enabled")
		}
		if c.Hysteria2.KeyPath == "" {
			errs = append(errs, "hysteria2.key_path is required when hysteria2 is enabled")
		}
	}

	if c.SS2022 != nil && c.SS2022.Enabled {
		if err := validatePort("ss2022.port", c.SS2022.Port); err != nil {
			errs = append(errs, err.Error())
		}
		if c.SS2022.Method == "" {
			errs = append(errs, "ss2022.method is required when ss2022 is enabled")
		}
		if c.SS2022.Key == "" {
			errs = append(errs, "ss2022.key is required when ss2022 is enabled")
		}
	}

	if c.WireGuard != nil && c.WireGuard.Enabled {
		if err := validatePort("wireguard.port", c.WireGuard.Port); err != nil {
			errs = append(errs, err.Error())
		}
		if c.WireGuard.PrivateKey == "" {
			errs = append(errs, "wireguard.private_key is required when wireguard is enabled")
		}
		if c.WireGuard.PublicKey == "" {
			errs = append(errs, "wireguard.public_key is required when wireguard is enabled")
		}
	}

	if c.CDNWebSocket != nil && c.CDNWebSocket.Enabled {
		if err := validatePort("cdn_websocket.port", c.CDNWebSocket.Port); err != nil {
			errs = append(errs, err.Error())
		}
		if c.CDNWebSocket.Path == "" {
			errs = append(errs, "cdn_websocket.path is required when cdn_websocket is enabled")
		}
		if c.CDNWebSocket.Host == "" {
			errs = append(errs, "cdn_websocket.host is required when cdn_websocket is enabled")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
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
	if err := cfg.Validate(); err != nil {
		return nil, err
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

type RotateKeysResult struct {
	PublicKey string
	ShortID   string
}

func RotateKeys(cfg *ServerConfig) (*RotateKeysResult, error) {
	keys, err := shared.GenerateRealityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate reality keypair: %w", err)
	}

	jwtSecret, err := shared.GeneratePassword(32)
	if err != nil {
		return nil, fmt.Errorf("generate jwt secret: %w", err)
	}

	shortID, err := shared.GenerateShortID()
	if err != nil {
		return nil, fmt.Errorf("generate short id: %w", err)
	}

	if cfg.RealityPublicKey != "" {
		cfg.LegacyPublicKeys = append(cfg.LegacyPublicKeys, cfg.RealityPublicKey)
	}

	cfg.RealityPrivateKey = keys.PrivateKey
	cfg.RealityPublicKey = keys.PublicKey
	cfg.ShortID = shortID
	cfg.JWTSecret = jwtSecret

	return &RotateKeysResult{
		PublicKey: keys.PublicKey,
		ShortID:   shortID,
	}, nil
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
