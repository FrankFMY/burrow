package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/FrankFMY/burrow/internal/server/store"
)

type Server struct {
	config      *ServerConfig
	transport   *Transport
	store       store.Store
	api         *API
	httpSrv     *http.Server
	metricsStop chan struct{}
	stopOnce    sync.Once
}

func New(cfg *ServerConfig) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	db, err := store.NewSQLite(cfg.DatabasePath())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := syncUsersToStore(context.Background(), db, cfg); err != nil {
		db.Close()
		return nil, fmt.Errorf("sync users: %w", err)
	}

	transport, err := NewTransport(cfg)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init transport: %w", err)
	}

	auth := NewAuth([]byte(cfg.JWTSecret))
	api := NewAPI(db, auth, cfg, cfg.ServerAddr)
	api.logBuffer = NewLogBuffer(500)

	return &Server{
		config:      cfg,
		transport:   transport,
		store:       db,
		api:         api,
		metricsStop: make(chan struct{}),
	}, nil
}

func (s *Server) SetConfigPath(path string) {
	s.api.SetConfigPath(path)
}

func (s *Server) Start() error {
	slog.Info("starting burrow server",
		"port", s.config.ListenPort,
		"api_port", s.config.APIPort,
		"camouflage", s.config.CamouflageSNI,
	)

	if err := s.transport.Start(); err != nil {
		return fmt.Errorf("start transport: %w", err)
	}

	addr := fmt.Sprintf(":%d", s.config.APIPort)
	s.httpSrv = &http.Server{
		Addr:         addr,
		Handler:      s.api.Router(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen api: %w", err)
	}

	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("api server error", "error", err)
		}
	}()

	go s.runMetricsUpdater()
	go s.api.tracker.Run()

	slog.Info("burrow server running",
		"vless_reality", fmt.Sprintf(":%d", s.config.ListenPort),
		"api", addr,
	)
	return nil
}

func (s *Server) Wait() {
	s.transport.Wait()
}

func (s *Server) runMetricsUpdater() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.api.metrics.Update(s.store, s.api.startedAt, s.api.tracker.ActiveSessions())
		case <-s.metricsStop:
			return
		}
	}
}

func (s *Server) Stop() error {
	slog.Info("stopping burrow server")
	s.stopOnce.Do(func() {
		close(s.metricsStop)
	})
	s.api.tracker.Close()
	close(s.api.loginRL.stop)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.httpSrv != nil {
		if err := s.httpSrv.Shutdown(ctx); err != nil {
			slog.Error("http server shutdown", "error", err)
		}
	}

	if err := s.transport.Close(); err != nil {
		slog.Error("transport close error", "error", err)
	}

	return s.store.Close()
}

func syncUsersToStore(ctx context.Context, db store.Store, cfg *ServerConfig) error {
	for _, u := range cfg.Users {
		existing, err := db.GetClientByToken(ctx, u.UUID)
		if err != nil {
			return err
		}
		if existing != nil {
			continue
		}
		client := &store.Client{
			ID:        u.UUID,
			Name:      u.Name,
			Token:     u.UUID,
			CreatedAt: time.Now().UTC(),
		}
		if err := db.CreateClient(ctx, client); err != nil {
			return fmt.Errorf("sync user %s: %w", u.Name, err)
		}
	}
	return nil
}
