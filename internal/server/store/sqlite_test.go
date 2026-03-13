package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	s, err := NewSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestClientCRUD(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	c := &Client{
		ID:        "test-id",
		Name:      "Test User",
		Token:     "test-token",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}

	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := s.GetClient(ctx, "test-id")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("client not found")
	}
	if got.Name != "Test User" {
		t.Errorf("name: got %q, want %q", got.Name, "Test User")
	}

	gotByToken, err := s.GetClientByToken(ctx, "test-token")
	if err != nil {
		t.Fatalf("get by token: %v", err)
	}
	if gotByToken == nil || gotByToken.ID != "test-id" {
		t.Error("get by token failed")
	}

	clients, err := s.ListClients(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(clients) != 1 {
		t.Errorf("list count: got %d, want 1", len(clients))
	}

	if err := s.RevokeClient(ctx, "test-id"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	revoked, err := s.GetClientByToken(ctx, "test-token")
	if err != nil {
		t.Fatalf("get revoked: %v", err)
	}
	if revoked != nil {
		t.Error("revoked client should not be returned by GetClientByToken")
	}
}

func TestActiveTokens(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	s.CreateClient(ctx, &Client{ID: "a", Name: "A", Token: "token-a", CreatedAt: time.Now()})
	s.CreateClient(ctx, &Client{ID: "b", Name: "B", Token: "token-b", CreatedAt: time.Now()})
	s.RevokeClient(ctx, "b")

	tokens, err := s.ListActiveTokens(ctx)
	if err != nil {
		t.Fatalf("list active tokens: %v", err)
	}
	if len(tokens) != 1 || tokens[0] != "token-a" {
		t.Errorf("active tokens: got %v, want [token-a]", tokens)
	}
}

func TestStats(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	s.CreateClient(ctx, &Client{ID: "a", Name: "A", Token: "ta", CreatedAt: time.Now()})
	s.CreateClient(ctx, &Client{ID: "b", Name: "B", Token: "tb", CreatedAt: time.Now()})
	s.RevokeClient(ctx, "b")

	stats, err := s.GetStats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.TotalClients != 2 {
		t.Errorf("total: got %d, want 2", stats.TotalClients)
	}
	if stats.ActiveClients != 1 {
		t.Errorf("active: got %d, want 1", stats.ActiveClients)
	}
	if stats.RevokedClients != 1 {
		t.Errorf("revoked: got %d, want 1", stats.RevokedClients)
	}
}

func TestConfig(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	val, err := s.GetConfig(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("get missing: %v", err)
	}
	if val != "" {
		t.Errorf("missing key should return empty, got %q", val)
	}

	if err := s.SetConfig(ctx, "key1", "value1"); err != nil {
		t.Fatalf("set: %v", err)
	}

	val, err = s.GetConfig(ctx, "key1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if val != "value1" {
		t.Errorf("got %q, want %q", val, "value1")
	}

	if err := s.SetConfig(ctx, "key1", "value2"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	val, _ = s.GetConfig(ctx, "key1")
	if val != "value2" {
		t.Errorf("upsert: got %q, want %q", val, "value2")
	}
}

func TestConnections(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	s.CreateClient(ctx, &Client{ID: "c1", Name: "C1", Token: "t1", CreatedAt: time.Now()})

	conn := &Connection{
		ClientID:    "c1",
		ConnectedAt: time.Now(),
		Protocol:    "vless",
	}
	if err := s.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if conn.ID == 0 {
		t.Error("connection ID should be set")
	}

	if err := s.CloseConnection(ctx, conn.ID, 1024, 2048); err != nil {
		t.Fatalf("close connection: %v", err)
	}

	conns, err := s.GetClientConnections(ctx, "c1", 10)
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("connections count: got %d, want 1", len(conns))
	}
	if conns[0].BytesUp != 1024 || conns[0].BytesDown != 2048 {
		t.Errorf("bytes: got %d/%d, want 1024/2048", conns[0].BytesUp, conns[0].BytesDown)
	}
}

func TestUpdateClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	c := &Client{
		ID:        "upd-1",
		Name:      "Update Me",
		Token:     "upd-token",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	c.BytesUp = 1024
	c.BytesDown = 2048
	c.LastProtocol = "vless-reality"
	c.LastConnectedAt = &now

	if err := s.UpdateClient(ctx, c); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := s.GetClient(ctx, "upd-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.BytesUp != 1024 {
		t.Errorf("bytes_up: got %d, want 1024", got.BytesUp)
	}
	if got.BytesDown != 2048 {
		t.Errorf("bytes_down: got %d, want 2048", got.BytesDown)
	}
	if got.LastProtocol != "vless-reality" {
		t.Errorf("last_protocol: got %q, want %q", got.LastProtocol, "vless-reality")
	}
	if got.LastConnectedAt == nil {
		t.Fatal("last_connected_at should be set")
	}
	if !got.LastConnectedAt.Equal(now) {
		t.Errorf("last_connected_at: got %v, want %v", got.LastConnectedAt, now)
	}
}

func TestRecordTraffic(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	c := &Client{
		ID:        "rec-1",
		Name:      "Record Me",
		Token:     "rec-token",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := s.RecordTraffic(ctx, "rec-token", 100, 200); err != nil {
		t.Fatalf("record traffic 1: %v", err)
	}
	if err := s.RecordTraffic(ctx, "rec-token", 100, 200); err != nil {
		t.Fatalf("record traffic 2: %v", err)
	}

	got, err := s.GetClientByToken(ctx, "rec-token")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("client not found")
	}
	if got.BytesUp != 200 {
		t.Errorf("bytes_up: got %d, want 200", got.BytesUp)
	}
	if got.BytesDown != 400 {
		t.Errorf("bytes_down: got %d, want 400", got.BytesDown)
	}
	if got.LastConnectedAt == nil {
		t.Error("last_connected_at should be set after RecordTraffic")
	}
}

func TestRecordTrafficRevokedClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	c := &Client{
		ID:        "rev-1",
		Name:      "Revoke Me",
		Token:     "rev-token",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.RevokeClient(ctx, "rev-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if err := s.RecordTraffic(ctx, "rev-token", 500, 1000); err != nil {
		t.Fatalf("record traffic: %v", err)
	}

	got, err := s.GetClient(ctx, "rev-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.BytesUp != 0 {
		t.Errorf("bytes_up: got %d, want 0 (revoked client should not be updated)", got.BytesUp)
	}
	if got.BytesDown != 0 {
		t.Errorf("bytes_down: got %d, want 0 (revoked client should not be updated)", got.BytesDown)
	}
}

func TestRecordAudit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.RecordAudit(ctx, "login", "admin", "", "", "192.168.1.1"); err != nil {
		t.Fatalf("record audit: %v", err)
	}

	entries, err := s.ListAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries count: got %d, want 1", len(entries))
	}
	if entries[0].Action != "login" {
		t.Errorf("action: got %q, want %q", entries[0].Action, "login")
	}
	if entries[0].Actor != "admin" {
		t.Errorf("actor: got %q, want %q", entries[0].Actor, "admin")
	}
	if entries[0].IP != "192.168.1.1" {
		t.Errorf("ip: got %q, want %q", entries[0].IP, "192.168.1.1")
	}
	if entries[0].Timestamp == "" {
		t.Error("timestamp should be set")
	}
	if entries[0].ID == 0 {
		t.Error("id should be set")
	}
}

func TestListAuditLog(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	s.RecordAudit(ctx, "login", "admin", "", "", "10.0.0.1")
	s.RecordAudit(ctx, "create_invite", "admin", "alice", "id=abc", "10.0.0.1")
	s.RecordAudit(ctx, "revoke_client", "admin", "client-1", "", "10.0.0.1")

	entries, err := s.ListAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries count: got %d, want 3", len(entries))
	}
	if entries[0].Action != "revoke_client" {
		t.Errorf("first entry should be most recent: got %q", entries[0].Action)
	}
	if entries[2].Action != "login" {
		t.Errorf("last entry should be oldest: got %q", entries[2].Action)
	}
	if entries[1].Target != "alice" {
		t.Errorf("target: got %q, want %q", entries[1].Target, "alice")
	}
	if entries[1].Detail != "id=abc" {
		t.Errorf("detail: got %q, want %q", entries[1].Detail, "id=abc")
	}
}

func TestListAuditLogLimit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		s.RecordAudit(ctx, "login", "admin", "", "", "10.0.0.1")
	}

	entries, err := s.ListAuditLog(ctx, 3)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("entries count: got %d, want 3", len(entries))
	}

	all, err := s.ListAuditLog(ctx, 0)
	if err != nil {
		t.Fatalf("list default: %v", err)
	}
	if len(all) != 10 {
		t.Errorf("default limit should return all (up to 50): got %d, want 10", len(all))
	}
}

func TestSQLiteFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	s, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("database file should exist after close")
	}
}
