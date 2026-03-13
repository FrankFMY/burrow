package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/FrankFMY/burrow/internal/server/store"
)

func setupTracker(t *testing.T) (*ConnectionTracker, *store.SQLiteStore) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.NewSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ct := NewConnectionTracker(db)
	return ct, db
}

func TestTrackerRecordConnect(t *testing.T) {
	ct, db := setupTracker(t)
	ctx := context.Background()

	db.CreateClient(ctx, &store.Client{
		ID: "c1", Name: "Client 1", Token: "token-1", CreatedAt: time.Now().UTC(),
	})

	connID, err := ct.RecordConnect(ctx, "token-1", "c1", "vless-reality")
	if err != nil {
		t.Fatalf("record connect: %v", err)
	}
	if connID == 0 {
		t.Error("connection ID should be non-zero")
	}

	if ct.ActiveSessions() != 1 {
		t.Errorf("active sessions: got %d, want 1", ct.ActiveSessions())
	}

	tokens := ct.ActiveTokens()
	if len(tokens) != 1 || tokens[0] != "token-1" {
		t.Errorf("active tokens: got %v, want [token-1]", tokens)
	}

	client, err := db.GetClientByToken(ctx, "token-1")
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if client.LastConnectedAt == nil {
		t.Error("last_connected_at should be set after connect")
	}

	conns, err := db.GetClientConnections(ctx, "c1", 10)
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("connections: got %d, want 1", len(conns))
	}
	if conns[0].Protocol != "vless-reality" {
		t.Errorf("protocol: got %q, want %q", conns[0].Protocol, "vless-reality")
	}
	if conns[0].DisconnectedAt != nil {
		t.Error("connection should still be open")
	}
}

func TestTrackerRecordDisconnect(t *testing.T) {
	ct, db := setupTracker(t)
	ctx := context.Background()

	db.CreateClient(ctx, &store.Client{
		ID: "c1", Name: "Client 1", Token: "token-1", CreatedAt: time.Now().UTC(),
	})

	ct.RecordConnect(ctx, "token-1", "c1", "vless-reality")

	if err := ct.RecordDisconnect(ctx, "token-1", 1024, 2048); err != nil {
		t.Fatalf("record disconnect: %v", err)
	}

	if ct.ActiveSessions() != 0 {
		t.Errorf("active sessions: got %d, want 0", ct.ActiveSessions())
	}

	client, err := db.GetClientByToken(ctx, "token-1")
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if client.BytesUp != 1024 {
		t.Errorf("bytes_up: got %d, want 1024", client.BytesUp)
	}
	if client.BytesDown != 2048 {
		t.Errorf("bytes_down: got %d, want 2048", client.BytesDown)
	}

	conns, err := db.GetClientConnections(ctx, "c1", 10)
	if err != nil {
		t.Fatalf("get connections: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("connections: got %d, want 1", len(conns))
	}
	if conns[0].DisconnectedAt == nil {
		t.Error("connection should be closed")
	}
	if conns[0].BytesUp != 1024 || conns[0].BytesDown != 2048 {
		t.Errorf("connection bytes: got %d/%d, want 1024/2048", conns[0].BytesUp, conns[0].BytesDown)
	}
}

func TestTrackerDisconnectUnknownToken(t *testing.T) {
	ct, _ := setupTracker(t)
	ctx := context.Background()

	err := ct.RecordDisconnect(ctx, "nonexistent", 100, 200)
	if err != nil {
		t.Fatalf("disconnect unknown token should not error: %v", err)
	}
}

func TestTrackerRecordHeartbeat(t *testing.T) {
	ct, db := setupTracker(t)
	ctx := context.Background()

	db.CreateClient(ctx, &store.Client{
		ID: "c1", Name: "Client 1", Token: "token-1", CreatedAt: time.Now().UTC(),
	})

	ct.RecordConnect(ctx, "token-1", "c1", "vless-reality")

	if err := ct.RecordHeartbeat(ctx, "token-1", 500, 1000); err != nil {
		t.Fatalf("record heartbeat: %v", err)
	}

	if ct.ActiveSessions() != 1 {
		t.Errorf("active sessions: got %d, want 1", ct.ActiveSessions())
	}

	client, err := db.GetClientByToken(ctx, "token-1")
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if client.BytesUp != 500 {
		t.Errorf("bytes_up: got %d, want 500", client.BytesUp)
	}
	if client.BytesDown != 1000 {
		t.Errorf("bytes_down: got %d, want 1000", client.BytesDown)
	}
}

func TestTrackerHeartbeatUnknownToken(t *testing.T) {
	ct, _ := setupTracker(t)
	ctx := context.Background()

	err := ct.RecordHeartbeat(ctx, "nonexistent", 100, 200)
	if err != nil {
		t.Fatalf("heartbeat unknown token should not error: %v", err)
	}
}

func TestTrackerMultipleHeartbeats(t *testing.T) {
	ct, db := setupTracker(t)
	ctx := context.Background()

	db.CreateClient(ctx, &store.Client{
		ID: "c1", Name: "Client 1", Token: "token-1", CreatedAt: time.Now().UTC(),
	})

	ct.RecordConnect(ctx, "token-1", "c1", "vless-reality")

	ct.RecordHeartbeat(ctx, "token-1", 100, 200)
	ct.RecordHeartbeat(ctx, "token-1", 100, 200)
	ct.RecordHeartbeat(ctx, "token-1", 100, 200)

	client, err := db.GetClientByToken(ctx, "token-1")
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if client.BytesUp != 300 {
		t.Errorf("bytes_up: got %d, want 300", client.BytesUp)
	}
	if client.BytesDown != 600 {
		t.Errorf("bytes_down: got %d, want 600", client.BytesDown)
	}
}

func TestTrackerConnectDisconnectMultipleClients(t *testing.T) {
	ct, db := setupTracker(t)
	ctx := context.Background()

	db.CreateClient(ctx, &store.Client{
		ID: "c1", Name: "Client 1", Token: "token-1", CreatedAt: time.Now().UTC(),
	})
	db.CreateClient(ctx, &store.Client{
		ID: "c2", Name: "Client 2", Token: "token-2", CreatedAt: time.Now().UTC(),
	})

	ct.RecordConnect(ctx, "token-1", "c1", "vless-reality")
	ct.RecordConnect(ctx, "token-2", "c2", "vless-reality")

	if ct.ActiveSessions() != 2 {
		t.Errorf("active sessions: got %d, want 2", ct.ActiveSessions())
	}

	ct.RecordHeartbeat(ctx, "token-1", 100, 200)
	ct.RecordDisconnect(ctx, "token-2", 500, 1000)

	if ct.ActiveSessions() != 1 {
		t.Errorf("active sessions after disconnect: got %d, want 1", ct.ActiveSessions())
	}

	c1, _ := db.GetClientByToken(ctx, "token-1")
	if c1.BytesUp != 100 {
		t.Errorf("c1 bytes_up: got %d, want 100", c1.BytesUp)
	}

	c2, _ := db.GetClient(ctx, "c2")
	if c2.BytesUp != 500 {
		t.Errorf("c2 bytes_up: got %d, want 500", c2.BytesUp)
	}
	if c2.BytesDown != 1000 {
		t.Errorf("c2 bytes_down: got %d, want 1000", c2.BytesDown)
	}
}

func TestTrackerTick(t *testing.T) {
	ct, db := setupTracker(t)
	ctx := context.Background()

	db.CreateClient(ctx, &store.Client{
		ID: "c1", Name: "Client 1", Token: "token-1", CreatedAt: time.Now().UTC(),
	})

	ct.RecordConnect(ctx, "token-1", "c1", "vless-reality")

	ct.tick()

	if ct.ActiveSessions() != 1 {
		t.Errorf("active sessions after tick: got %d, want 1", ct.ActiveSessions())
	}

	client, _ := db.GetClientByToken(ctx, "token-1")
	if client.LastConnectedAt == nil {
		t.Error("last_connected_at should be set after tick")
	}
}

func TestTrackerTickCleansStale(t *testing.T) {
	ct, db := setupTracker(t)
	ctx := context.Background()

	db.CreateClient(ctx, &store.Client{
		ID: "c1", Name: "Client 1", Token: "token-1", CreatedAt: time.Now().UTC(),
	})

	ct.RecordConnect(ctx, "token-1", "c1", "vless-reality")

	ct.mu.Lock()
	ct.sessions["token-1"].LastSeen = time.Now().Add(-2 * sessionStaleTimeout)
	ct.mu.Unlock()

	ct.tick()

	if ct.ActiveSessions() != 0 {
		t.Errorf("active sessions after stale cleanup: got %d, want 0", ct.ActiveSessions())
	}
}

func TestTrackerClose(t *testing.T) {
	ct, db := setupTracker(t)
	ctx := context.Background()

	db.CreateClient(ctx, &store.Client{
		ID: "c1", Name: "Client 1", Token: "token-1", CreatedAt: time.Now().UTC(),
	})
	db.CreateClient(ctx, &store.Client{
		ID: "c2", Name: "Client 2", Token: "token-2", CreatedAt: time.Now().UTC(),
	})

	ct.RecordConnect(ctx, "token-1", "c1", "vless-reality")
	ct.RecordConnect(ctx, "token-2", "c2", "vless-reality")

	ct.Close()

	if ct.ActiveSessions() != 0 {
		t.Errorf("active sessions after close: got %d, want 0", ct.ActiveSessions())
	}

	conns1, _ := db.GetClientConnections(ctx, "c1", 10)
	if len(conns1) != 1 {
		t.Fatalf("c1 connections: got %d, want 1", len(conns1))
	}
	if conns1[0].DisconnectedAt == nil {
		t.Error("c1 connection should be closed on shutdown")
	}

	conns2, _ := db.GetClientConnections(ctx, "c2", 10)
	if len(conns2) != 1 {
		t.Fatalf("c2 connections: got %d, want 1", len(conns2))
	}
	if conns2[0].DisconnectedAt == nil {
		t.Error("c2 connection should be closed on shutdown")
	}
}
