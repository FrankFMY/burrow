package store

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("not found")

type Client struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Token           string     `json:"token"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	Revoked         bool       `json:"revoked"`
	LastConnectedAt *time.Time `json:"last_connected_at,omitempty"`
	LastProtocol    string     `json:"last_protocol,omitempty"`
	BytesUp         int64      `json:"bytes_up"`
	BytesDown       int64      `json:"bytes_down"`
	BandwidthLimit  int64      `json:"bandwidth_limit"`
}

type Connection struct {
	ID             int64      `json:"id"`
	ClientID       string     `json:"client_id"`
	ConnectedAt    time.Time  `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
	Protocol       string     `json:"protocol"`
	BytesUp        int64      `json:"bytes_up"`
	BytesDown      int64      `json:"bytes_down"`
}

type Store interface {
	Close() error

	GetConfig(ctx context.Context, key string) (string, error)
	SetConfig(ctx context.Context, key, value string) error

	CreateClient(ctx context.Context, c *Client) error
	GetClient(ctx context.Context, id string) (*Client, error)
	GetClientByToken(ctx context.Context, token string) (*Client, error)
	ListClients(ctx context.Context) ([]Client, error)
	UpdateClient(ctx context.Context, c *Client) error
	RevokeClient(ctx context.Context, id string) error
	RecordTraffic(ctx context.Context, token string, bytesUp, bytesDown int64) error

	ListActiveTokens(ctx context.Context) ([]string, error)

	CreateConnection(ctx context.Context, c *Connection) error
	CloseConnection(ctx context.Context, id int64, bytesUp, bytesDown int64) error
	GetClientConnections(ctx context.Context, clientID string, limit int) ([]Connection, error)

	GetStats(ctx context.Context) (*Stats, error)

	RecordAudit(ctx context.Context, action, actor, target, detail, ip string) error
	ListAuditLog(ctx context.Context, limit int) ([]AuditEntry, error)
}

type AuditEntry struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Actor     string `json:"actor"`
	Target    string `json:"target,omitempty"`
	Detail    string `json:"detail,omitempty"`
	IP        string `json:"ip,omitempty"`
}

type Stats struct {
	TotalClients     int   `json:"total_clients"`
	ActiveClients    int   `json:"active_clients"`
	RevokedClients   int   `json:"revoked_clients"`
	TotalBytesUp     int64 `json:"total_bytes_up"`
	TotalBytesDown   int64 `json:"total_bytes_down"`
	TotalConnections int   `json:"total_connections"`
}
