package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(1)

	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return s, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			token TEXT UNIQUE NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			expires_at TEXT,
			revoked INTEGER NOT NULL DEFAULT 0,
			last_connected_at TEXT,
			last_protocol TEXT,
			bytes_up INTEGER NOT NULL DEFAULT 0,
			bytes_down INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS connections (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_id TEXT NOT NULL REFERENCES clients(id),
			connected_at TEXT NOT NULL DEFAULT (datetime('now')),
			disconnected_at TEXT,
			protocol TEXT NOT NULL,
			bytes_up INTEGER NOT NULL DEFAULT 0,
			bytes_down INTEGER NOT NULL DEFAULT 0
		);

		CREATE INDEX IF NOT EXISTS idx_clients_token ON clients(token);
		CREATE INDEX IF NOT EXISTS idx_connections_client ON connections(client_id);
	`)
	if err != nil {
		return err
	}

	// Add bandwidth_limit column if it doesn't exist (migration for existing databases).
	_, _ = s.db.Exec(`ALTER TABLE clients ADD COLUMN bandwidth_limit INTEGER NOT NULL DEFAULT 0`)

	return nil
}

func (s *SQLiteStore) GetConfig(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *SQLiteStore) SetConfig(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?", key, value, value)
	return err
}

func (s *SQLiteStore) CreateClient(ctx context.Context, c *Client) error {
	var expiresAt *string
	if c.ExpiresAt != nil {
		v := c.ExpiresAt.UTC().Format(time.RFC3339)
		expiresAt = &v
	}

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO clients (id, name, token, created_at, expires_at, bandwidth_limit) VALUES (?, ?, ?, ?, ?, ?)",
		c.ID, c.Name, c.Token, c.CreatedAt.UTC().Format(time.RFC3339), expiresAt, c.BandwidthLimit,
	)
	return err
}

func (s *SQLiteStore) GetClient(ctx context.Context, id string) (*Client, error) {
	return s.scanClient(s.db.QueryRowContext(ctx,
		"SELECT id, name, token, created_at, expires_at, revoked, last_connected_at, last_protocol, bytes_up, bytes_down, bandwidth_limit FROM clients WHERE id = ?", id,
	))
}

func (s *SQLiteStore) GetClientByToken(ctx context.Context, token string) (*Client, error) {
	return s.scanClient(s.db.QueryRowContext(ctx,
		"SELECT id, name, token, created_at, expires_at, revoked, last_connected_at, last_protocol, bytes_up, bytes_down, bandwidth_limit FROM clients WHERE token = ? AND revoked = 0", token,
	))
}

func (s *SQLiteStore) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, token, created_at, expires_at, revoked, last_connected_at, last_protocol, bytes_up, bytes_down, bandwidth_limit FROM clients ORDER BY created_at DESC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clients := make([]Client, 0)
	for rows.Next() {
		c, err := s.scanClientRow(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, *c)
	}
	return clients, rows.Err()
}

func (s *SQLiteStore) UpdateClient(ctx context.Context, c *Client) error {
	var lastConn *string
	if c.LastConnectedAt != nil {
		v := c.LastConnectedAt.UTC().Format(time.RFC3339)
		lastConn = &v
	}

	_, err := s.db.ExecContext(ctx,
		"UPDATE clients SET last_connected_at = ?, last_protocol = ?, bytes_up = ?, bytes_down = ? WHERE id = ?",
		lastConn, c.LastProtocol, c.BytesUp, c.BytesDown, c.ID,
	)
	return err
}

func (s *SQLiteStore) RecordTraffic(ctx context.Context, token string, bytesUp, bytesDown int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE clients SET bytes_up = bytes_up + ?, bytes_down = bytes_down + ?, last_connected_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE token = ? AND revoked = 0`,
		bytesUp, bytesDown, token)
	return err
}

func (s *SQLiteStore) RevokeClient(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, "UPDATE clients SET revoked = 1 WHERE id = ?", id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) ListActiveTokens(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT token FROM clients WHERE revoked = 0 AND (expires_at IS NULL OR expires_at > datetime('now'))",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tokens := make([]string, 0)
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *SQLiteStore) CreateConnection(ctx context.Context, c *Connection) error {
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO connections (client_id, connected_at, protocol) VALUES (?, ?, ?)",
		c.ClientID, c.ConnectedAt.UTC().Format(time.RFC3339), c.Protocol,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	c.ID = id
	return nil
}

func (s *SQLiteStore) CloseConnection(ctx context.Context, id int64, bytesUp, bytesDown int64) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE connections SET disconnected_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), bytes_up = ?, bytes_down = ? WHERE id = ?",
		bytesUp, bytesDown, id,
	)
	return err
}

func (s *SQLiteStore) GetClientConnections(ctx context.Context, clientID string, limit int) ([]Connection, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, client_id, connected_at, disconnected_at, protocol, bytes_up, bytes_down FROM connections WHERE client_id = ? ORDER BY connected_at DESC LIMIT ?",
		clientID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	conns := make([]Connection, 0)
	for rows.Next() {
		var c Connection
		var connAt, disconnAt *string
		if err := rows.Scan(&c.ID, &c.ClientID, &connAt, &disconnAt, &c.Protocol, &c.BytesUp, &c.BytesDown); err != nil {
			return nil, err
		}
		if connAt != nil {
			t, err := time.Parse(time.RFC3339, *connAt)
			if err != nil {
				slog.Warn("parse connected_at time", "value", *connAt, "error", err)
			}
			c.ConnectedAt = t
		}
		if disconnAt != nil {
			t, err := time.Parse(time.RFC3339, *disconnAt)
			if err != nil {
				slog.Warn("parse disconnected_at time", "value", *disconnAt, "error", err)
			}
			c.DisconnectedAt = &t
		}
		conns = append(conns, c)
	}
	return conns, rows.Err()
}

func (s *SQLiteStore) GetStats(ctx context.Context) (*Stats, error) {
	var stats Stats
	err := s.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) as total,
			COALESCE(SUM(CASE WHEN revoked = 0 THEN 1 ELSE 0 END), 0) as active,
			COALESCE(SUM(CASE WHEN revoked = 1 THEN 1 ELSE 0 END), 0) as revoked,
			COALESCE(SUM(bytes_up), 0) as bytes_up,
			COALESCE(SUM(bytes_down), 0) as bytes_down
		FROM clients
	`).Scan(&stats.TotalClients, &stats.ActiveClients, &stats.RevokedClients, &stats.TotalBytesUp, &stats.TotalBytesDown)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM connections").Scan(&stats.TotalConnections)
	if err != nil {
		return nil, err
	}

	return &stats, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func (s *SQLiteStore) scanClient(row *sql.Row) (*Client, error) {
	c, err := scanClientFields(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (s *SQLiteStore) scanClientRow(rows *sql.Rows) (*Client, error) {
	return scanClientFields(rows.Scan)
}

func scanClientFields(scan func(dest ...any) error) (*Client, error) {
	var c Client
	var createdAt, expiresAt, lastConn, lastProto *string
	var revoked int

	err := scan(&c.ID, &c.Name, &c.Token, &createdAt, &expiresAt, &revoked, &lastConn, &lastProto, &c.BytesUp, &c.BytesDown, &c.BandwidthLimit)
	if err != nil {
		return nil, err
	}

	c.Revoked = revoked != 0
	if createdAt != nil {
		t, err := time.Parse(time.RFC3339, *createdAt)
		if err != nil {
			slog.Warn("parse created_at time", "value", *createdAt, "error", err)
		}
		c.CreatedAt = t
	}
	if expiresAt != nil {
		t, err := time.Parse(time.RFC3339, *expiresAt)
		if err != nil {
			slog.Warn("parse expires_at time", "value", *expiresAt, "error", err)
		}
		c.ExpiresAt = &t
	}
	if lastConn != nil {
		t, err := time.Parse(time.RFC3339, *lastConn)
		if err != nil {
			slog.Warn("parse last_connected_at time", "value", *lastConn, "error", err)
		}
		c.LastConnectedAt = &t
	}
	if lastProto != nil {
		c.LastProtocol = *lastProto
	}

	return &c, nil
}
