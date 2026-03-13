package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/FrankFMY/burrow/internal/server"
	"github.com/FrankFMY/burrow/internal/shared"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "invite":
		cmdInvite(os.Args[2:])
	case "version":
		fmt.Printf("burrow-server %s (%s) built %s\n", shared.Version, shared.Commit, shared.BuildDate)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: burrow-server <command> [flags]

Commands:
  init      Initialize server configuration
  run       Start the server
  invite    Manage client invites
  version   Print version information
`)
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	port := fs.Uint("port", server.DefaultPort, "Listen port for VLESS+Reality")
	apiPort := fs.Uint("api-port", server.DefaultAPIPort, "API server port")
	sni := fs.String("camouflage", server.DefaultCamouflageSNI, "Camouflage SNI domain")
	password := fs.String("password", "", "Admin password (required)")
	serverAddr := fs.String("server", "", "Server public IP or domain (required)")
	dataDir := fs.String("data-dir", "/var/lib/burrow", "Data directory for database")
	configPath := fs.String("config", server.DefaultConfigPath(), "Config file path")
	fs.Parse(args)

	if *password == "" {
		fmt.Fprintf(os.Stderr, "Error: --password is required\n")
		os.Exit(1)
	}
	if *serverAddr == "" {
		fmt.Fprintf(os.Stderr, "Error: --server is required (your VPS IP or domain)\n")
		os.Exit(1)
	}

	if _, err := os.Stat(*configPath); err == nil {
		fmt.Fprintf(os.Stderr, "Config already exists at %s. Delete it first to reinitialize.\n", *configPath)
		os.Exit(1)
	}

	cfg, err := server.GenerateConfig(uint16(*port), uint16(*apiPort), *sni, *password, *serverAddr, *dataDir)
	if err != nil {
		slog.Error("failed to generate config", "error", err)
		os.Exit(1)
	}

	if err := server.SaveConfig(*configPath, cfg); err != nil {
		slog.Error("failed to save config", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Server initialized.\n")
	fmt.Printf("  Config:     %s\n", *configPath)
	fmt.Printf("  Port:       %d (VLESS+Reality)\n", cfg.ListenPort)
	fmt.Printf("  API Port:   %d\n", cfg.APIPort)
	fmt.Printf("  Camouflage: %s\n", cfg.CamouflageSNI)
	fmt.Printf("  Public key: %s\n", cfg.RealityPublicKey)
	fmt.Printf("  Server:     %s\n", cfg.ServerAddr)
	fmt.Printf("\nStart the server:\n  burrow-server run --config %s\n", *configPath)
	fmt.Printf("\nCreate an invite:\n  burrow-server invite create --config %s --name \"My phone\"\n", *configPath)
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", server.DefaultConfigPath(), "Config file path")
	fs.Parse(args)

	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err, "path", *configPath)
		os.Exit(1)
	}

	srv, err := server.New(cfg)
	if err != nil {
		slog.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	if err := srv.Start(); err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}

	srv.Wait()

	if err := srv.Stop(); err != nil {
		slog.Error("error during shutdown", "error", err)
	}
}

func cmdInvite(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: burrow-server invite <create|list>\n")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	configPath := fs.String("config", server.DefaultConfigPath(), "Config file path")
	name := fs.String("name", "", "Client name")
	fs.Parse(args[1:])

	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	switch args[0] {
	case "create":
		if *name == "" {
			fmt.Fprintf(os.Stderr, "Error: --name is required\n")
			os.Exit(1)
		}

		user, err := server.AddUser(cfg, *name)
		if err != nil {
			slog.Error("failed to add user", "error", err)
			os.Exit(1)
		}

		if err := server.SaveConfig(*configPath, cfg); err != nil {
			slog.Error("failed to save config", "error", err)
			os.Exit(1)
		}

		invite := shared.InviteData{
			Server:    cfg.ServerAddr,
			Port:      cfg.ListenPort,
			Token:     user.UUID,
			SNI:       cfg.CamouflageSNI,
			PublicKey: cfg.RealityPublicKey,
			ShortID:   cfg.ShortID,
			Name:      *name,
		}
		link, err := shared.EncodeInvite(invite)
		if err != nil {
			slog.Error("failed to encode invite", "error", err)
			os.Exit(1)
		}
		fmt.Printf("Invite created for %q:\n  %s\n", *name, link)

	case "list":
		for _, u := range cfg.Users {
			fmt.Printf("  %s  %s\n", u.UUID, u.Name)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown invite command: %s\n", args[0])
		os.Exit(1)
	}
}
