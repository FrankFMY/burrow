package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/clashapi"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/FrankFMY/burrow/internal/client/killswitch"
	"github.com/FrankFMY/burrow/internal/shared"
)

type TransportMode string

const (
	TransportDirect TransportMode = "direct"
	TransportCDN    TransportMode = "cdn"
)

type TunnelOptions struct {
	Invite      shared.InviteData
	KillSwitch  bool
	TUNMode     bool
	SplitTunnel *SplitTunnelConfig
	Transport   TransportMode
}

const tunInterfaceName = "utun-burrow"

type Tunnel struct {
	instance    *box.Box
	ctx         context.Context
	cancel      context.CancelFunc
	registryCtx context.Context
	ks          killswitch.KillSwitch
	serverIP    string
	tunMode     bool
}

func NewTunnel(topts TunnelOptions) (*Tunnel, error) {
	transport := topts.Transport
	if transport == "" {
		transport = TransportDirect
	}

	registryCtx := include.Context(context.Background())
	ctx, cancel := context.WithCancel(registryCtx)

	opts, err := buildClientOptions(registryCtx, topts.Invite, topts.TUNMode, topts.SplitTunnel, transport)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("build client config: %w", err)
	}

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create sing-box instance: %w", err)
	}

	t := &Tunnel{instance: instance, ctx: ctx, cancel: cancel, registryCtx: registryCtx, serverIP: topts.Invite.Server, tunMode: topts.TUNMode}
	if topts.KillSwitch {
		t.ks = killswitch.New()
	}
	return t, nil
}

func probeServer(addr string, port uint16, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", addr, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func NewTunnelWithFallback(topts TunnelOptions) (*Tunnel, TransportMode, error) {
	modes := []TransportMode{TransportDirect}
	if topts.Invite.CDNHost != "" {
		modes = append(modes, TransportCDN)
	}

	if topts.Transport != "" {
		topts.Transport = topts.Transport
		t, err := NewTunnel(topts)
		return t, topts.Transport, err
	}

	if probeServer(topts.Invite.Server, topts.Invite.Port, 5*time.Second) {
		topts.Transport = TransportDirect
		t, err := NewTunnel(topts)
		if err == nil {
			return t, TransportDirect, nil
		}
		slog.Warn("direct transport failed to initialize", "error", err)
	} else {
		slog.Info("direct server unreachable, trying fallback", "server", topts.Invite.Server, "port", topts.Invite.Port)
	}

	if topts.Invite.CDNHost != "" {
		slog.Info("falling back to CDN transport", "host", topts.Invite.CDNHost)
		topts.Transport = TransportCDN
		t, err := NewTunnel(topts)
		if err == nil {
			return t, TransportCDN, nil
		}
		slog.Warn("CDN transport failed to initialize", "error", err)
	}

	topts.Transport = TransportDirect
	t, err := NewTunnel(topts)
	return t, TransportDirect, err
}

func (t *Tunnel) Stats() (up, down int64) {
	clashServer := service.FromContext[adapter.ClashServer](t.registryCtx)
	if clashServer == nil {
		return 0, 0
	}
	if s, ok := clashServer.(*clashapi.Server); ok {
		return s.TrafficManager().Total()
	}
	return 0, 0
}

func (t *Tunnel) Start() error {
	if err := t.instance.Start(); err != nil {
		return fmt.Errorf("start tunnel: %w", err)
	}
	slog.Info("tunnel started", "proxy", "127.0.0.1:1080")

	if t.ks != nil {
		if err := t.ks.Enable(tunInterfaceName, t.serverIP, "1.1.1.1"); err != nil {
			slog.Warn("kill switch failed to enable", "error", err)
		}
	}
	return nil
}

func (t *Tunnel) Close() error {
	if t.ks != nil && t.ks.IsEnabled() {
		if err := t.ks.Disable(); err != nil {
			slog.Warn("kill switch failed to disable", "error", err)
		}
	}
	t.cancel()
	return t.instance.Close()
}

func (t *Tunnel) Healthy() bool {
	if t.ctx.Err() != nil {
		return false
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1080", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (t *Tunnel) Wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	s := <-sig
	slog.Info("received signal", "signal", s)
}

func buildClientConfigMap(invite shared.InviteData, tunMode bool, st *SplitTunnelConfig, transport ...TransportMode) map[string]any {
	mode := TransportDirect
	if len(transport) > 0 && transport[0] != "" {
		mode = transport[0]
	}

	inbounds := []any{
		map[string]any{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": 1080,
		},
	}

	if tunMode {
		inbounds = append(inbounds, map[string]any{
			"type":                       "tun",
			"tag":                        "tun-in",
			"interface_name":             tunInterfaceName,
			"address":                    []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"mtu":                        9000,
			"auto_route":                 true,
			"strict_route":               true,
			"stack":                      "gvisor",
			"sniff":                      true,
			"sniff_override_destination": true,
		})
	}

	routeRules := []map[string]any{
		{
			"action":   "hijack-dns",
			"protocol": []string{"dns"},
		},
	}

	if tunMode {
		routeRules = append(routeRules, map[string]any{
			"action":   "route",
			"ip_cidr":  []string{invite.Server + "/32"},
			"outbound": "direct-out",
		})
	}

	if st != nil && st.Enabled {
		if len(st.BypassDomains) > 0 {
			routeRules = append(routeRules, map[string]any{
				"action":        "route",
				"domain_suffix": st.BypassDomains,
				"outbound":      "direct-out",
			})
		}
		if len(st.BypassIPs) > 0 {
			routeRules = append(routeRules, map[string]any{
				"action":   "route",
				"ip_cidr":  st.BypassIPs,
				"outbound": "direct-out",
			})
		}
	}

	dnsRules := []map[string]any{
		{
			"outbound": []string{"any"},
			"server":   "remote-doh",
		},
	}

	if st != nil && st.Enabled && len(st.BypassDomains) > 0 {
		dnsRules = append(dnsRules, map[string]any{
			"domain_suffix": st.BypassDomains,
			"server":        "local-dns",
		})
	}

	var outbounds []any

	switch mode {
	case TransportCDN:
		cdnPort := invite.CDNPort
		if cdnPort == 0 {
			cdnPort = 443
		}
		cdnPath := invite.CDNPath
		if cdnPath == "" {
			cdnPath = "/ws"
		}
		outbounds = []any{
			map[string]any{
				"type":        "vless",
				"tag":         "vless-out",
				"server":      invite.CDNHost,
				"server_port": cdnPort,
				"uuid":        invite.Token,
				"tls": map[string]any{
					"enabled":     true,
					"server_name": invite.CDNHost,
				},
				"transport": map[string]any{
					"type": "ws",
					"path": cdnPath,
					"headers": map[string]any{
						"Host": invite.CDNHost,
					},
				},
			},
		}
	default:
		outbounds = []any{
			map[string]any{
				"type":        "vless",
				"tag":         "vless-out",
				"server":      invite.Server,
				"server_port": invite.Port,
				"uuid":        invite.Token,
				"tls": map[string]any{
					"enabled":     true,
					"server_name": invite.SNI,
					"utls": map[string]any{
						"enabled":     true,
						"fingerprint": "chrome",
					},
					"reality": map[string]any{
						"enabled":    true,
						"public_key": invite.PublicKey,
						"short_id":   invite.ShortID,
					},
				},
			},
		}
	}

	outbounds = append(outbounds, map[string]any{
		"type": "direct",
		"tag":  "direct-out",
	})

	return map[string]any{
		"experimental": map[string]any{
			"clash_api": map[string]any{},
		},
		"log": map[string]any{
			"level": "info",
		},
		"dns": map[string]any{
			"servers": []map[string]any{
				{
					"tag":     "remote-doh",
					"address": "https://1.1.1.1/dns-query",
					"detour":  "vless-out",
				},
				{
					"tag":     "local-dns",
					"address": "223.5.5.5",
					"detour":  "direct-out",
				},
			},
			"rules": dnsRules,
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"rules": routeRules,
			"final": "vless-out",
		},
	}
}

func buildClientOptions(ctx context.Context, invite shared.InviteData, tunMode bool, st *SplitTunnelConfig, transport TransportMode) (option.Options, error) {
	configMap := buildClientConfigMap(invite, tunMode, st, transport)

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
