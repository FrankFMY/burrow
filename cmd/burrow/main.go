package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/FrankFMY/burrow/internal/client"
	"github.com/FrankFMY/burrow/internal/shared"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "connect":
		cmdConnect(os.Args[2:])
	case "daemon":
		cmdDaemon(os.Args[2:])
	case "servers":
		cmdServers(os.Args[2:])
	case "version":
		fmt.Printf("burrow %s (%s) built %s\n", shared.Version, shared.Commit, shared.BuildDate)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: burrow <command> [flags]

Commands:
  connect [invite-link]   Connect to server (invite link or last used)
  daemon                  Run background daemon (API on 127.0.0.1:9090)
  servers list            List configured servers
  servers add <link>      Add server from invite link
  servers remove <name>   Remove server
  version                 Print version information
`)
}

func cmdConnect(args []string) {
	connectFlags := flag.NewFlagSet("connect", flag.ExitOnError)
	killSwitchFlag := connectFlags.Bool("kill-switch", false, "Enable kill switch (block traffic if tunnel drops)")

	var invite shared.InviteData
	var err error

	var positional []string
	for _, a := range args {
		if a == "--kill-switch" || a == "-kill-switch" {
			*killSwitchFlag = true
		} else {
			positional = append(positional, a)
		}
	}

	if len(positional) > 0 && positional[0] != "" {
		invite, err = shared.DecodeInvite(positional[0])
		if err != nil {
			slog.Error("invalid invite link", "error", err)
			os.Exit(1)
		}

		cfg, loadErr := client.LoadClientConfig()
		if loadErr != nil {
			slog.Error("load config", "error", loadErr)
			os.Exit(1)
		}
		cfg.AddServer(invite)
		cfg.Last = invite.Server
		client.SaveClientConfig(cfg)
	} else {
		cfg, err := client.LoadClientConfig()
		if err != nil {
			slog.Error("load config", "error", err)
			os.Exit(1)
		}
		srv := cfg.GetLastServer()
		if srv == nil {
			fmt.Fprintf(os.Stderr, "No servers configured. Use: burrow connect <invite-link>\n")
			os.Exit(1)
		}
		invite = srv.Invite
	}

	name := invite.Name
	if name == "" {
		name = invite.Server
	}

	slog.Info("connecting",
		"server", invite.Server,
		"port", invite.Port,
		"sni", invite.SNI,
		"name", name,
	)

	tunnel, err := client.NewTunnel(client.TunnelOptions{
		Invite:     invite,
		KillSwitch: *killSwitchFlag,
	})
	if err != nil {
		slog.Error("failed to create tunnel", "error", err)
		os.Exit(1)
	}

	if err := tunnel.Start(); err != nil {
		slog.Error("failed to start tunnel", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Connected to %s via VLESS+Reality\n", name)
	fmt.Printf("SOCKS5/HTTP proxy: 127.0.0.1:1080\n")
	if *killSwitchFlag {
		fmt.Printf("Kill switch: enabled\n")
	}

	tunnel.Wait()

	if err := tunnel.Close(); err != nil {
		slog.Error("error during shutdown", "error", err)
	}
	fmt.Println("Disconnected.")
}

func cmdDaemon(args []string) {
	addr := "127.0.0.1:9090"
	if len(args) > 0 {
		addr = args[0]
	}

	d, err := client.NewDaemon()
	if err != nil {
		slog.Error("failed to create daemon", "error", err)
		os.Exit(1)
	}

	slog.Info("starting daemon", "addr", addr)
	if err := d.Start(addr); err != nil {
		slog.Error("daemon error", "error", err)
		os.Exit(1)
	}
}

func cmdServers(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: burrow servers <list|add|remove>\n")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		cfg, err := client.LoadClientConfig()
		if err != nil {
			slog.Error("load config", "error", err)
			os.Exit(1)
		}
		if len(cfg.Servers) == 0 {
			fmt.Println("No servers configured.")
			return
		}
		for _, s := range cfg.Servers {
			marker := " "
			if s.Invite.Server == cfg.Last {
				marker = "*"
			}
			fmt.Printf(" %s %-20s %s:%d (%s)\n", marker, s.Name, s.Invite.Server, s.Invite.Port, s.Invite.SNI)
		}

	case "add":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: burrow servers add <invite-link>\n")
			os.Exit(1)
		}
		invite, err := shared.DecodeInvite(args[1])
		if err != nil {
			slog.Error("invalid invite link", "error", err)
			os.Exit(1)
		}
		cfg, loadErr := client.LoadClientConfig()
		if loadErr != nil {
			slog.Error("load config", "error", loadErr)
			os.Exit(1)
		}
		cfg.AddServer(invite)
		if err := client.SaveClientConfig(cfg); err != nil {
			slog.Error("save config", "error", err)
			os.Exit(1)
		}
		name := invite.Name
		if name == "" {
			name = invite.Server
		}
		fmt.Printf("Added server: %s (%s:%d)\n", name, invite.Server, invite.Port)

	case "remove":
		fs := flag.NewFlagSet("remove", flag.ExitOnError)
		fs.Parse(args[1:])
		if fs.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "Usage: burrow servers remove <name>\n")
			os.Exit(1)
		}
		target := fs.Arg(0)
		cfg, err := client.LoadClientConfig()
		if err != nil {
			slog.Error("load config", "error", err)
			os.Exit(1)
		}
		found := false
		for i, s := range cfg.Servers {
			if s.Name == target || s.Invite.Server == target {
				cfg.Servers = append(cfg.Servers[:i], cfg.Servers[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Server %q not found\n", target)
			os.Exit(1)
		}
		if err := client.SaveClientConfig(cfg); err != nil {
			slog.Error("save config", "error", err)
			os.Exit(1)
		}
		fmt.Printf("Removed server: %s\n", target)

	default:
		fmt.Fprintf(os.Stderr, "Unknown servers command: %s\n", args[0])
		os.Exit(1)
	}
}
