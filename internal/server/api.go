package server

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	embedfs "github.com/FrankFMY/burrow/embed"
	"github.com/FrankFMY/burrow/internal/server/store"
	"github.com/FrankFMY/burrow/internal/shared"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

type API struct {
	store      store.Store
	auth       *Auth
	config     *ServerConfig
	configPath string
	serverAddr string
	loginRL    *loginRateLimiter
}

func NewAPI(s store.Store, auth *Auth, cfg *ServerConfig, serverAddr string) *API {
	rl := newLoginRateLimiter()
	go rl.cleanup()
	return &API{
		store:      s,
		auth:       auth,
		config:     cfg,
		serverAddr: serverAddr,
		loginRL:    rl,
	}
}

func (a *API) SetConfigPath(path string) {
	a.configPath = path
}

func (a *API) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	r.Get("/health", a.handleHealth)

	r.Post("/api/auth/login", a.handleLogin)

	r.Post("/api/connect", a.handleConnect)

	r.Group(func(r chi.Router) {
		r.Use(a.auth.Middleware)

		r.Post("/api/auth/logout", a.handleLogout)

		r.Get("/api/invites", a.handleListInvites)
		r.Post("/api/invites", a.handleCreateInvite)
		r.Delete("/api/invites/{id}", a.handleRevokeInvite)

		r.Get("/api/clients", a.handleListClients)
		r.Get("/api/clients/{id}", a.handleGetClient)
		r.Delete("/api/clients/{id}", a.handleRevokeClient)

		r.Get("/api/stats", a.handleGetStats)
		r.Get("/api/config", a.handleGetConfig)
		r.Post("/api/rotate-keys", a.handleRotateKeys)
	})

	r.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
	})
	r.Handle("/admin/*", a.adminHandler())

	r.Get("/", a.handleLanding)

	return r
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": shared.Version,
	})
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.SplitN(fwd, ",", 2)[0]
		ip = strings.TrimSpace(ip)
	}

	if !a.loginRL.allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts, try again later"})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if !CheckPassword(a.config.AdminPasswordHash, req.Password) {
		a.loginRL.record(ip)
		time.Sleep(500 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
		return
	}

	a.loginRL.reset(ip)

	token, err := a.auth.GenerateToken("admin", 24*time.Hour)
	if err != nil {
		slog.Error("generate token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token  string `json:"token"`
		Invite string `json:"invite,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	if req.Invite != "" {
		data, err := shared.VerifyInvite(req.Invite, a.config.JWTSecret)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid invite signature"})
			return
		}
		req.Token = data.Token
	}

	client, err := a.store.GetClientByToken(r.Context(), req.Token)
	if err != nil {
		slog.Error("get client by token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if client == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	if client.ExpiresAt != nil && client.ExpiresAt.Before(time.Now()) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invite expired"})
		return
	}

	protocols := []map[string]any{
		{
			"type":        "vless",
			"server":      a.serverAddr,
			"server_port": a.config.ListenPort,
			"uuid":        client.Token,
			"tls": map[string]any{
				"server_name": a.config.CamouflageSNI,
				"reality": map[string]any{
					"public_key": a.config.RealityPublicKey,
					"short_id":   a.config.ShortID,
				},
			},
		},
	}

	if a.config.Hysteria2 != nil && a.config.Hysteria2.Enabled {
		protocols = append(protocols, map[string]any{
			"type":        "hysteria2",
			"server":      a.serverAddr,
			"server_port": a.config.Hysteria2.Port,
			"password":    a.config.Hysteria2.Password,
		})
	}
	if a.config.SS2022 != nil && a.config.SS2022.Enabled {
		protocols = append(protocols, map[string]any{
			"type":        "shadowsocks",
			"server":      a.serverAddr,
			"server_port": a.config.SS2022.Port,
			"method":      a.config.SS2022.Method,
			"password":    a.config.SS2022.Key,
		})
	}
	if a.config.WireGuard != nil && a.config.WireGuard.Enabled {
		protocols = append(protocols, map[string]any{
			"type":        "wireguard",
			"server":      a.serverAddr,
			"server_port": a.config.WireGuard.Port,
			"public_key":  a.config.WireGuard.PublicKey,
		})
	}
	if a.config.CDNWebSocket != nil && a.config.CDNWebSocket.Enabled && a.config.CDNWebSocket.Host != "" {
		protocols = append(protocols, map[string]any{
			"type":     "vless-ws",
			"cdn_host": a.config.CDNWebSocket.Host,
			"cdn_port": 443,
			"cdn_path": a.config.CDNWebSocket.Path,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"client_id": client.ID,
		"name":      client.Name,
		"protocols": protocols,
	})
}

func (a *API) handleListInvites(w http.ResponseWriter, r *http.Request) {
	clients, err := a.store.ListClients(r.Context())
	if err != nil {
		slog.Error("list clients", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (a *API) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		ExpiresIn string `json:"expires_in,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}

	client := &store.Client{
		ID:        uuid.New().String(),
		Name:      req.Name,
		Token:     uuid.New().String(),
		CreatedAt: time.Now().UTC(),
	}

	if req.ExpiresIn != "" {
		dur, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid expires_in duration"})
			return
		}
		exp := time.Now().Add(dur)
		client.ExpiresAt = &exp
	}

	if err := a.store.CreateClient(r.Context(), client); err != nil {
		slog.Error("create client", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	invite := shared.InviteData{
		Server:    a.serverAddr,
		Port:      a.config.ListenPort,
		Token:     client.Token,
		SNI:       a.config.CamouflageSNI,
		PublicKey: a.config.RealityPublicKey,
		ShortID:   a.config.ShortID,
		Name:      client.Name,
	}
	if a.config.CDNWebSocket != nil && a.config.CDNWebSocket.Enabled && a.config.CDNWebSocket.Host != "" {
		invite.CDNHost = a.config.CDNWebSocket.Host
		invite.CDNPort = 443
		invite.CDNPath = a.config.CDNWebSocket.Path
	}
	invite.Sig = shared.SignInvite(invite, a.config.JWTSecret)
	link, err := shared.EncodeInvite(invite)
	if err != nil {
		slog.Error("encode invite", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"client": client,
		"invite": link,
	})
}

func (a *API) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := a.store.RevokeClient(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "invite not found"})
			return
		}
		slog.Error("revoke client", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (a *API) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := a.store.ListClients(r.Context())
	if err != nil {
		slog.Error("list clients", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (a *API) handleGetClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	client, err := a.store.GetClient(r.Context(), id)
	if err != nil {
		slog.Error("get client", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if client == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (a *API) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := a.store.RevokeClient(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
			return
		}
		slog.Error("revoke client", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (a *API) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := a.store.GetStats(r.Context())
	if err != nil {
		slog.Error("get stats", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (a *API) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"listen_port": a.config.ListenPort,
		"camouflage":  a.config.CamouflageSNI,
		"public_key":  a.config.RealityPublicKey,
		"short_id":    a.config.ShortID,
		"server_addr": a.serverAddr,
	})
}

func (a *API) handleRotateKeys(w http.ResponseWriter, r *http.Request) {
	if a.configPath == "" {
		slog.Error("rotate keys: config path not set")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "config path not configured"})
		return
	}

	result, err := RotateKeys(a.config)
	if err != nil {
		slog.Error("rotate keys", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate new keys"})
		return
	}

	if err := SaveConfig(a.configPath, a.config); err != nil {
		slog.Error("save config after key rotation", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save config"})
		return
	}

	a.auth.UpdateSecret([]byte(a.config.JWTSecret))

	slog.Info("keys rotated", "public_key", result.PublicKey, "short_id", result.ShortID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "rotated",
		"public_key": result.PublicKey,
		"short_id":   result.ShortID,
	})
}

func (a *API) adminHandler() http.Handler {
	sub, err := fs.Sub(embedfs.AdminFS, "admin")
	if err != nil {
		slog.Error("embed admin fs", "error", err)
		return http.NotFoundHandler()
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/admin/")
		if path == "" {
			path = "index.html"
		}

		if _, err := fs.Stat(sub, path); err != nil {
			r.URL.Path = "/admin/index.html"
		}

		http.StripPrefix("/admin", fileServer).ServeHTTP(w, r)
	})
}

func (a *API) handleLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(embedfs.LandingHTML)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

const (
	loginMaxAttempts = 5
	loginWindow      = time.Minute
	loginCleanupFreq = 5 * time.Minute
)

type loginAttempt struct {
	count   int
	firstAt time.Time
}

type loginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		attempts: make(map[string]*loginAttempt),
	}
}

func (rl *loginRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	a, ok := rl.attempts[ip]
	if !ok {
		return true
	}
	if time.Since(a.firstAt) > loginWindow {
		delete(rl.attempts, ip)
		return true
	}
	return a.count < loginMaxAttempts
}

func (rl *loginRateLimiter) record(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	a, ok := rl.attempts[ip]
	if !ok || time.Since(a.firstAt) > loginWindow {
		rl.attempts[ip] = &loginAttempt{count: 1, firstAt: time.Now()}
		return
	}
	a.count++
}

func (rl *loginRateLimiter) reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
}

func (rl *loginRateLimiter) cleanup() {
	for {
		time.Sleep(loginCleanupFreq)
		rl.mu.Lock()
		now := time.Now()
		for ip, a := range rl.attempts {
			if now.Sub(a.firstAt) > loginWindow {
				delete(rl.attempts, ip)
			}
		}
		rl.mu.Unlock()
	}
}
