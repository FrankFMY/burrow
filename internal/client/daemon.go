package client

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/FrankFMY/burrow/internal/shared"
)

type Daemon struct {
	mu        sync.Mutex
	tunnel    *Tunnel
	config    *ClientConfig
	startTime time.Time
	server    *http.Server
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

	d.server = &http.Server{
		Addr:    addr,
		Handler: corsWrap(mux),
	}

	slog.Info("client daemon listening", "addr", addr)
	return d.server.ListenAndServe()
}

func (d *Daemon) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tunnel != nil {
		d.tunnel.Close()
		d.tunnel = nil
	}
	if d.server != nil {
		d.server.Close()
	}
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.tunnel == nil {
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"running": false,
		})
		return
	}

	uptime := int(time.Since(d.startTime).Seconds())
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"running":     true,
		"server":      d.tunnel.serverIP,
		"protocol":    "vless-reality",
		"uptime":      uptime,
		"bytes_up":    0,
		"bytes_down":  0,
		"kill_switch": d.tunnel.ks != nil && d.tunnel.ks.IsEnabled(),
	})
}

func (d *Daemon) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server     string `json:"server"`
		KillSwitch bool   `json:"kill_switch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.tunnel != nil {
		writeJSONResponse(w, http.StatusConflict, map[string]string{"error": "already connected"})
		return
	}

	cfg, err := LoadClientConfig()
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		writeJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "no server found"})
		return
	}

	tunnel, err := NewTunnel(TunnelOptions{
		Invite:     entry.Invite,
		KillSwitch: req.KillSwitch,
	})
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if err := tunnel.Start(); err != nil {
		tunnel.Close()
		writeJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	d.tunnel = tunnel
	d.startTime = time.Now()

	cfg.Last = entry.Invite.Server
	if err := SaveClientConfig(cfg); err != nil {
		slog.Warn("save client config", "error", err)
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "connected"})
}

func (d *Daemon) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.tunnel == nil {
		writeJSONResponse(w, http.StatusOK, map[string]string{"status": "not connected"})
		return
	}

	if err := d.tunnel.Close(); err != nil {
		slog.Error("tunnel close", "error", err)
	}
	d.tunnel = nil

	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "disconnected"})
}

func (d *Daemon) handleListServers(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cfg, _ := LoadClientConfig()

	var servers []map[string]any
	for _, s := range cfg.Servers {
		servers = append(servers, map[string]any{
			"name":      s.Name,
			"address":   s.Invite.Server,
			"port":      s.Invite.Port,
			"sni":       s.Invite.SNI,
			"connected": d.tunnel != nil && d.tunnel.serverIP == s.Invite.Server,
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

func (d *Daemon) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"version":    shared.Version,
		"config_dir": ConfigDir(),
	})
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func corsWrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
