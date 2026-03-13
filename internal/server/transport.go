package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

type Transport struct {
	instance *box.Box
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewTransport(cfg *ServerConfig) (*Transport, error) {
	registryCtx := include.Context(context.Background())
	ctx, cancel := context.WithCancel(registryCtx)

	opts, err := buildSingboxOptions(registryCtx, cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("build config: %w", err)
	}

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create sing-box instance: %w", err)
	}

	return &Transport{instance: instance, ctx: ctx, cancel: cancel}, nil
}

func (t *Transport) Start() error {
	if err := t.instance.Start(); err != nil {
		return fmt.Errorf("start transport: %w", err)
	}
	slog.Info("transport started")
	return nil
}

func (t *Transport) Close() error {
	t.cancel()
	return t.instance.Close()
}

func (t *Transport) Wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	s := <-sig
	signal.Stop(sig)
	slog.Info("received signal, shutting down", "signal", s)
}

func buildSingboxOptions(ctx context.Context, cfg *ServerConfig) (option.Options, error) {
	users := make([]map[string]string, len(cfg.Users))
	for i, u := range cfg.Users {
		users[i] = map[string]string{"name": u.Name, "uuid": u.UUID}
	}

	inbounds := []any{
		buildVLESSRealityInbound(cfg, users),
	}

	if cfg.Hysteria2 != nil && cfg.Hysteria2.Enabled {
		inbounds = append(inbounds, buildHysteria2Inbound(cfg))
	}
	if cfg.SS2022 != nil && cfg.SS2022.Enabled {
		inbounds = append(inbounds, buildSS2022Inbound(cfg))
	}
	if cfg.WireGuard != nil && cfg.WireGuard.Enabled {
		inbounds = append(inbounds, buildWireGuardInbound(cfg))
	}

	configMap := map[string]any{
		"log": map[string]any{
			"level": "info",
		},
		"dns": map[string]any{
			"servers": []map[string]any{
				{
					"tag":     "cloudflare-doh",
					"address": "https://1.1.1.1/dns-query",
				},
			},
		},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{
				"type": "direct",
				"tag":  "direct-out",
			},
		},
		"route": map[string]any{
			"rules": []map[string]any{
				{
					"action":   "hijack-dns",
					"protocol": []string{"dns"},
				},
			},
			"final": "direct-out",
		},
	}

	b, err := json.Marshal(configMap)
	if err != nil {
		return option.Options{}, fmt.Errorf("marshal config: %w", err)
	}

	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, b)
	if err != nil {
		return option.Options{}, fmt.Errorf("parse sing-box config: %w", err)
	}

	return opts, nil
}

func buildVLESSRealityInbound(cfg *ServerConfig, users []map[string]string) map[string]any {
	return map[string]any{
		"type":        "vless",
		"tag":         "vless-reality-in",
		"listen":      "::",
		"listen_port": cfg.ListenPort,
		"users":       users,
		"tls": map[string]any{
			"enabled":     true,
			"server_name": cfg.CamouflageSNI,
			"reality": map[string]any{
				"enabled": true,
				"handshake": map[string]any{
					"server":      cfg.CamouflageSNI,
					"server_port": 443,
				},
				"private_key": cfg.RealityPrivateKey,
				"short_id":    []string{cfg.ShortID},
			},
		},
	}
}

func buildHysteria2Inbound(cfg *ServerConfig) map[string]any {
	return map[string]any{
		"type":        "hysteria2",
		"tag":         "hysteria2-in",
		"listen":      "::",
		"listen_port": cfg.Hysteria2.Port,
		"users": []map[string]string{
			{"password": cfg.Hysteria2.Password},
		},
		"tls": map[string]any{
			"enabled":          true,
			"server_name":      cfg.CamouflageSNI,
			"certificate_path": cfg.Hysteria2.CertPath,
			"key_path":         cfg.Hysteria2.KeyPath,
		},
	}
}

func buildSS2022Inbound(cfg *ServerConfig) map[string]any {
	return map[string]any{
		"type":        "shadowsocks",
		"tag":         "ss2022-in",
		"listen":      "::",
		"listen_port": cfg.SS2022.Port,
		"method":      cfg.SS2022.Method,
		"password":    cfg.SS2022.Key,
	}
}

func buildWireGuardInbound(cfg *ServerConfig) map[string]any {
	return map[string]any{
		"type":        "wireguard",
		"tag":         "wireguard-in",
		"listen":      "::",
		"listen_port": cfg.WireGuard.Port,
		"private_key": cfg.WireGuard.PrivateKey,
		"peers": []map[string]any{
			{
				"allowed_ips": []string{"0.0.0.0/0", "::/0"},
			},
		},
	}
}
