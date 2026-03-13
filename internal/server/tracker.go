package server

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/FrankFMY/burrow/internal/server/store"
)

const (
	sessionStaleTimeout = 1 * time.Hour
	trackingInterval    = 60 * time.Second
)

type activeSession struct {
	Token        string
	ConnectionID int64
	LastSeen     time.Time
}

type ConnectionTracker struct {
	mu       sync.Mutex
	sessions map[string]*activeSession // keyed by token
	store    store.Store
	stop     chan struct{}
}

func NewConnectionTracker(s store.Store) *ConnectionTracker {
	return &ConnectionTracker{
		sessions: make(map[string]*activeSession),
		store:    s,
		stop:     make(chan struct{}),
	}
}

func (ct *ConnectionTracker) RecordConnect(ctx context.Context, token, clientID, protocol string) (int64, error) {
	conn := &store.Connection{
		ClientID:    clientID,
		ConnectedAt: time.Now().UTC(),
		Protocol:    protocol,
	}
	if err := ct.store.CreateConnection(ctx, conn); err != nil {
		return 0, err
	}

	if err := ct.store.RecordTraffic(ctx, token, 0, 0); err != nil {
		slog.Warn("record connect touch failed", "token", token, "error", err)
	}

	ct.mu.Lock()
	ct.sessions[token] = &activeSession{
		Token:        token,
		ConnectionID: conn.ID,
		LastSeen:     time.Now(),
	}
	ct.mu.Unlock()

	return conn.ID, nil
}

func (ct *ConnectionTracker) RecordDisconnect(ctx context.Context, token string, bytesUp, bytesDown int64) error {
	ct.mu.Lock()
	sess, ok := ct.sessions[token]
	if ok {
		delete(ct.sessions, token)
	}
	ct.mu.Unlock()

	if !ok {
		return nil
	}

	if err := ct.store.CloseConnection(ctx, sess.ConnectionID, bytesUp, bytesDown); err != nil {
		slog.Warn("close connection failed", "id", sess.ConnectionID, "error", err)
	}

	return ct.store.RecordTraffic(ctx, token, bytesUp, bytesDown)
}

func (ct *ConnectionTracker) RecordHeartbeat(ctx context.Context, token string, bytesUp, bytesDown int64) error {
	ct.mu.Lock()
	sess, ok := ct.sessions[token]
	if ok {
		sess.LastSeen = time.Now()
	}
	ct.mu.Unlock()

	if !ok {
		return nil
	}

	return ct.store.RecordTraffic(ctx, token, bytesUp, bytesDown)
}

func (ct *ConnectionTracker) ActiveSessions() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return len(ct.sessions)
}

func (ct *ConnectionTracker) ActiveTokens() []string {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	tokens := make([]string, 0, len(ct.sessions))
	for t := range ct.sessions {
		tokens = append(tokens, t)
	}
	return tokens
}

func (ct *ConnectionTracker) Run() {
	ticker := time.NewTicker(trackingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ct.tick()
		case <-ct.stop:
			return
		}
	}
}

func (ct *ConnectionTracker) tick() {
	ct.mu.Lock()
	now := time.Now()
	var stale []string
	var active []string
	for token, sess := range ct.sessions {
		if now.Sub(sess.LastSeen) > sessionStaleTimeout {
			stale = append(stale, token)
		} else {
			active = append(active, token)
		}
	}

	staleConnIDs := make(map[string]int64, len(stale))
	for _, token := range stale {
		staleConnIDs[token] = ct.sessions[token].ConnectionID
		delete(ct.sessions, token)
	}
	ct.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for token, connID := range staleConnIDs {
		if err := ct.store.CloseConnection(ctx, connID, 0, 0); err != nil {
			slog.Warn("close stale connection", "token", token, "error", err)
		}
		slog.Debug("cleaned up stale session", "token", token)
	}

	for _, token := range active {
		if err := ct.store.RecordTraffic(ctx, token, 0, 0); err != nil {
			slog.Warn("touch active session", "token", token, "error", err)
		}
	}

	if len(stale) > 0 {
		slog.Info("session tracker tick", "active", len(active), "stale_cleaned", len(stale))
	}
}

func (ct *ConnectionTracker) Close() {
	close(ct.stop)

	ct.mu.Lock()
	remaining := make(map[string]int64, len(ct.sessions))
	for token, sess := range ct.sessions {
		remaining[token] = sess.ConnectionID
	}
	ct.sessions = make(map[string]*activeSession)
	ct.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for token, connID := range remaining {
		if err := ct.store.CloseConnection(ctx, connID, 0, 0); err != nil {
			slog.Warn("close session on shutdown", "token", token, "error", err)
		}
	}
}
