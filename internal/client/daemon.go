package client

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/FrankFMY/burrow/internal/shared"
)

const (
	healthCheckInterval = 5 * time.Second
	maxReconnectDelay   = 30 * time.Second
	maxReconnectAttempt = 10
)

type Daemon struct {
	mu               sync.Mutex
	tunnel           *Tunnel
	config           *ClientConfig
	startTime        time.Time
	server           *http.Server
	reconnecting     bool
	reconnectAttempt int
	lastError        string
	lastTunnelOpts   TunnelOptions
	stopHealth       chan struct{}
	reconnectDone    chan struct{}
}

func NewDaemon() (*Daemon, error) {
	cfg, err := LoadClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return &Daemon{config: cfg}, nil
}

func (d *Daemon) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", d.handleStatus)
	mux.HandleFunc("POST /api/connect", d.handleConnect)
	mux.HandleFunc("POST /api/disconnect", d.handleDisconnect)
	mux.HandleFunc("GET /api/servers", d.handleListServers)
	mux.HandleFunc("POST /api/servers", d.handleAddServer)
	mux.HandleFunc("DELETE /api/servers/{name}", d.handleRemoveServer)
	mux.HandleFunc("GET /api/version", d.handleVersion)
	mux.HandleFunc("GET /api/servers/{name}/ping", d.handlePingServer)
	mux.HandleFunc("GET /api/preferences", d.handleGetPreferences)
	mux.HandleFunc("PUT /api/preferences", d.handleSetPreferences)

	d.server = &http.Server{
		Addr:         addr,
		Handler:      corsWrap(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("client daemon listening", "addr", addr)
	return d.server.ListenAndServe()
}

func (d *Daemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopHealthMonitor()
	if d.tunnel != nil {
		d.tunnel.Close()
		d.tunnel = nil
	}
	if d.server != nil {
		d.server.Close()
	}
}

func (d *Daemon) startHealthMonitor() {
	d.stopHealthMonitor()
	d.stopHealth = make(chan struct{})
	go d.healthLoop()
}

func (d *Daemon) stopHealthMonitor() {
	if d.stopHealth != nil {
		close(d.stopHealth)
		d.stopHealth = nil
	}
}

func (d *Daemon) healthLoop() {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopHealth:
			return
		case <-ticker.C:
			d.checkAndReconnect()
		}
	}
}

func (d *Daemon) checkAndReconnect() {
	d.mu.Lock()

	if d.tunnel == nil || d.reconnecting {
		d.mu.Unlock()
		return
	}

	if d.tunnel.Healthy() {
		d.mu.Unlock()
		return
	}

	slog.Warn("tunnel health check failed, starting reconnect")
	d.reconnecting = true
	d.reconnectAttempt = 0
	opts := d.lastTunnelOpts
	stopCh := d.stopHealth
	done := make(chan struct{})
	d.reconnectDone = done

	d.tunnel.Close()
	d.tunnel = nil

	d.mu.Unlock()

	d.reconnectLoop(opts, stopCh, done)
}

func (d *Daemon) reconnectLoop(opts TunnelOptions, stopCh <-chan struct{}, done chan struct{}) {
	defer close(done)

	for attempt := 1; attempt <= maxReconnectAttempt; attempt++ {
		delay := reconnectDelay(attempt)
		slog.Info("reconnect attempt", "attempt", attempt, "delay", delay)

		select {
		case <-stopCh:
			d.mu.Lock()
			d.reconnecting = false
			d.mu.Unlock()
			return
		case <-time.After(delay):
		}

		select {
		case <-stopCh:
			d.mu.Lock()
			d.reconnecting = false
			d.mu.Unlock()
			return
		default:
		}

		tunnel, err := NewTunnel(opts)
		if err != nil {
			d.mu.Lock()
			d.reconnectAttempt = attempt
			d.lastError = err.Error()
			d.mu.Unlock()
			slog.Warn("reconnect: create tunnel failed", "attempt", attempt, "error", err)
			continue
		}

		if err := tunnel.Start(); err != nil {
			tunnel.Close()
			d.mu.Lock()
			d.reconnectAttempt = attempt
			d.lastError = err.Error()
			d.mu.Unlock()
			slog.Warn("reconnect: start tunnel failed", "attempt", attempt, "error", err)
			continue
		}

		d.mu.Lock()
		select {
		case <-stopCh:
			d.reconnecting = false
			d.mu.Unlock()
			tunnel.Close()
			slog.Info("reconnect: cancelled after tunnel started (disconnect requested)")
			return
		default:
		}
		d.tunnel = tunnel
		d.startTime = time.Now()
		d.reconnecting = false
		d.reconnectAttempt = 0
		d.lastError = ""
		d.reconnectDone = nil
		d.mu.Unlock()

		slog.Info("reconnect successful", "attempt", attempt)
		return
	}

	d.mu.Lock()
	d.reconnecting = false
	d.lastError = fmt.Sprintf("reconnect failed after %d attempts", maxReconnectAttempt)
	d.mu.Unlock()

	slog.Error("all reconnect attempts exhausted")
}

func reconnectDelay(attempt int) time.Duration {
	delay := time.Second
	for i := 1; i < attempt; i++ {
		delay *= 2
	}
	if delay > maxReconnectDelay {
		delay = maxReconnectDelay
	}
	return delay
}

func friendlyError(err error) (code string, message string) {
	s := strings.ToLower(err.Error())

	switch {
	case strings.Contains(s, "permission denied") || strings.Contains(s, "operation not permitted"):
		return "PERMISSION_DENIED", "Administrator rights required for VPN mode. Run the application as administrator."
	case strings.Contains(s, "context deadline exceeded") || strings.Contains(s, "i/o timeout"):
		return "TIMEOUT", "Connection to server timed out. Check your internet connection."
	case strings.Contains(s, "connection refused"):
		return "SERVER_UNREACHABLE", "Server is unreachable. It may be down or blocked."
	case strings.Contains(s, "address already in use"):
		return "PORT_IN_USE", "Port 1080 is already in use by another application."
	case strings.Contains(s, "no such host") || strings.Contains(s, "no such device"):
		return "DNS_ERROR", "Cannot resolve server address. Check your DNS settings."
	case strings.Contains(s, "certificate") || strings.Contains(s, "tls"):
		return "TLS_ERROR", "Secure connection failed. Server configuration may have changed."
	default:
		short := err.Error()
		if len(short) > 120 {
			short = short[:120] + "..."
		}
		return "UNKNOWN", "Connection failed: " + short
	}
}

func writeErrorResponse(w http.ResponseWriter, status int, err error) {
	code, message := friendlyError(err)
	writeJSONResponse(w, status, map[string]string{
		"error":      message,
		"error_code": code,
		"detail":     err.Error(),
	})
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.tunnel == nil {
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"running":           false,
			"reconnecting":      d.reconnecting,
			"reconnect_attempt": d.reconnectAttempt,
			"last_error":        d.lastError,
		})
		return
	}

	uptime := int(time.Since(d.startTime).Seconds())
	bytesUp, bytesDown := d.tunnel.Stats()
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"running":           true,
		"reconnecting":      d.reconnecting,
		"reconnect_attempt": d.reconnectAttempt,
		"last_error":        d.lastError,
		"server":            d.tunnel.serverIP,
		"protocol":          "vless-reality",
		"uptime":            uptime,
		"bytes_up":          bytesUp,
		"bytes_down":        bytesDown,
		"kill_switch":       d.tunnel.ks != nil && d.tunnel.ks.IsEnabled(),
		"tun_mode":          d.tunnel.tunMode,
	})
}

func (d *Daemon) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server     string `json:"server"`
		KillSwitch bool   `json:"kill_switch"`
		TUNMode    bool   `json:"tun_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	d.mu.Lock()

	if d.tunnel != nil || d.reconnecting {
		d.mu.Unlock()
		writeJSONResponse(w, http.StatusConflict, map[string]string{"error": "already connected"})
		return
	}

	cfg, err := LoadClientConfig()
	if err != nil {
		d.mu.Unlock()
		writeErrorResponse(w, http.StatusInternalServerError, err)
		return
	}
	d.config = cfg

	var entry *ServerEntry
	if req.Server != "" {
		entry = cfg.GetServer(req.Server)
	} else {
		entry = cfg.GetLastServer()
	}
	if entry == nil {
		d.mu.Unlock()
		writeJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "no server found"})
		return
	}

	opts := TunnelOptions{
		Invite:      entry.Invite,
		KillSwitch:  req.KillSwitch,
		TUNMode:     req.TUNMode,
		SplitTunnel: cfg.SplitTunnel,
	}
	d.mu.Unlock()

	tunnel, mode, err := NewTunnelWithFallback(opts)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, err)
		return
	}

	if err := tunnel.Start(); err != nil {
		tunnel.Close()
		writeErrorResponse(w, http.StatusInternalServerError, err)
		return
	}
	slog.Info("connected", "transport", mode)

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.tunnel != nil || d.reconnecting {
		tunnel.Close()
		writeJSONResponse(w, http.StatusConflict, map[string]string{"error": "already connected"})
		return
	}

	d.lastError = ""
	d.tunnel = tunnel
	d.startTime = time.Now()
	d.lastTunnelOpts = opts
	d.reconnecting = false
	d.reconnectAttempt = 0
	d.startHealthMonitor()

	cfg.Last = entry.Invite.Server
	if err := SaveClientConfig(cfg); err != nil {
		slog.Warn("save client config", "error", err)
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "connected"})
}

func (d *Daemon) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()

	d.stopHealthMonitor()

	wasReconnecting := d.reconnecting
	doneCh := d.reconnectDone

	if wasReconnecting && doneCh != nil {
		d.mu.Unlock()

		select {
		case <-doneCh:
		case <-time.After(5 * time.Second):
			slog.Warn("timed out waiting for reconnect goroutine to finish")
		}

		d.mu.Lock()
	}

	d.reconnecting = false
	d.reconnectAttempt = 0
	d.lastError = ""
	d.reconnectDone = nil

	if d.tunnel == nil {
		d.mu.Unlock()
		if wasReconnecting {
			writeJSONResponse(w, http.StatusOK, map[string]string{"status": "cancelled"})
		} else {
			writeJSONResponse(w, http.StatusOK, map[string]string{"status": "not connected"})
		}
		return
	}

	tunnel := d.tunnel
	d.tunnel = nil
	d.mu.Unlock()

	if err := tunnel.Close(); err != nil {
		slog.Error("tunnel close", "error", err)
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "disconnected"})
}

func (d *Daemon) handleListServers(w http.ResponseWriter, r *http.Request) {
	cfg, err := LoadClientConfig()
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	d.mu.Lock()
	connectedServer := ""
	if d.tunnel != nil {
		connectedServer = d.tunnel.serverIP
	}
	d.mu.Unlock()

	var servers []map[string]any
	for _, s := range cfg.Servers {
		servers = append(servers, map[string]any{
			"name":      s.Name,
			"address":   s.Invite.Server,
			"port":      s.Invite.Port,
			"sni":       s.Invite.SNI,
			"connected": connectedServer == s.Invite.Server,
			"protocol":  "vless-reality",
		})
	}
	if servers == nil {
		servers = []map[string]any{}
	}
	writeJSONResponse(w, http.StatusOK, servers)
}

func (d *Daemon) handleAddServer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Invite string `json:"invite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	invite, err := shared.DecodeInvite(req.Invite)
	if err != nil {
		writeJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid invite link"})
		return
	}

	cfg, err := LoadClientConfig()
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	cfg.AddServer(invite)
	if err := SaveClientConfig(cfg); err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	name := invite.Name
	if name == "" {
		name = invite.Server
	}
	writeJSONResponse(w, http.StatusCreated, map[string]any{
		"name":    name,
		"address": invite.Server,
		"port":    invite.Port,
		"sni":     invite.SNI,
	})
}

func (d *Daemon) handleRemoveServer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	cfg, err := LoadClientConfig()
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	found := false
	for i, s := range cfg.Servers {
		if s.Name == name || s.Invite.Server == name {
			cfg.Servers = append(cfg.Servers[:i], cfg.Servers[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		writeJSONResponse(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}

	if err := SaveClientConfig(cfg); err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (d *Daemon) handlePingServer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	cfg, err := LoadClientConfig()
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var addr string
	var port uint16
	for _, s := range cfg.Servers {
		if s.Name == name || s.Invite.Server == name {
			addr = s.Invite.Server
			port = s.Invite.Port
			break
		}
	}
	if addr == "" {
		writeJSONResponse(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}

	target := net.JoinHostPort(addr, fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"server":    name,
			"reachable": false,
			"latency":   -1,
		})
		return
	}
	latency := time.Since(start).Milliseconds()
	conn.Close()

	writeJSONResponse(w, http.StatusOK, map[string]any{
		"server":    name,
		"reachable": true,
		"latency":   latency,
	})
}

func (d *Daemon) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"version":    shared.Version,
		"config_dir": ConfigDir(),
	})
}

func (d *Daemon) handleGetPreferences(w http.ResponseWriter, r *http.Request) {
	cfg, err := LoadClientConfig()
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"tun_mode":     cfg.GetTUNMode(),
		"kill_switch":  cfg.KillSwitch,
		"auto_connect": cfg.AutoConnect,
		"split_tunnel": cfg.SplitTunnel,
	})
}

func (d *Daemon) handleSetPreferences(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TUNMode     *bool              `json:"tun_mode"`
		KillSwitch  *bool              `json:"kill_switch"`
		AutoConnect *bool              `json:"auto_connect"`
		SplitTunnel *SplitTunnelConfig `json:"split_tunnel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	cfg, err := LoadClientConfig()
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if req.TUNMode != nil {
		cfg.SetTUNMode(*req.TUNMode)
	}
	if req.KillSwitch != nil {
		cfg.KillSwitch = *req.KillSwitch
	}
	if req.AutoConnect != nil {
		cfg.AutoConnect = *req.AutoConnect
	}
	if req.SplitTunnel != nil {
		cfg.SplitTunnel = req.SplitTunnel
	}

	if err := SaveClientConfig(cfg); err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]any{
		"tun_mode":     cfg.GetTUNMode(),
		"kill_switch":  cfg.KillSwitch,
		"auto_connect": cfg.AutoConnect,
		"split_tunnel": cfg.SplitTunnel,
	})
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("json encode response", "error", err)
	}
}

func corsWrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "http://localhost:5173" || origin == "http://127.0.0.1:5173" || origin == "tauri://localhost" || origin == "https://tauri.localhost" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
