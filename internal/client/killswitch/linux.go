//go:build linux

package killswitch

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

const iptablesChain = "BURROW_KILLSWITCH"

type LinuxKillSwitch struct {
	enabled bool
}

func New() KillSwitch {
	return &LinuxKillSwitch{}
}

func (k *LinuxKillSwitch) Enable(tunnelInterface, serverIP, dnsIP string) error {
	k.Disable()

	commands := []string{
		fmt.Sprintf("iptables -N %s", iptablesChain),
		fmt.Sprintf("iptables -A %s -o lo -j ACCEPT", iptablesChain),
		fmt.Sprintf("iptables -A %s -o %s -j ACCEPT", iptablesChain, tunnelInterface),
		fmt.Sprintf("iptables -A %s -d %s -j ACCEPT", iptablesChain, serverIP),
		fmt.Sprintf("iptables -A %s -d 127.0.0.0/8 -j ACCEPT", iptablesChain),
		fmt.Sprintf("iptables -A %s -d 10.0.0.0/8 -j ACCEPT", iptablesChain),
		fmt.Sprintf("iptables -A %s -d 172.16.0.0/12 -j ACCEPT", iptablesChain),
		fmt.Sprintf("iptables -A %s -d 192.168.0.0/16 -j ACCEPT", iptablesChain),
		fmt.Sprintf("iptables -A %s -p udp --dport 67:68 -j ACCEPT", iptablesChain),
		fmt.Sprintf("iptables -A %s -j DROP", iptablesChain),
		fmt.Sprintf("iptables -I OUTPUT 1 -j %s", iptablesChain),
	}

	for _, cmd := range commands {
		if err := runIPTables(cmd); err != nil {
			k.Disable()
			return fmt.Errorf("enable kill switch: %w (cmd: %s)", err, cmd)
		}
	}

	ip6Commands := []string{
		fmt.Sprintf("ip6tables -N %s", iptablesChain),
		fmt.Sprintf("ip6tables -A %s -o lo -j ACCEPT", iptablesChain),
		fmt.Sprintf("ip6tables -A %s -o %s -j ACCEPT", iptablesChain, tunnelInterface),
		fmt.Sprintf("ip6tables -A %s -d ::1/128 -j ACCEPT", iptablesChain),
		fmt.Sprintf("ip6tables -A %s -j DROP", iptablesChain),
		fmt.Sprintf("ip6tables -I OUTPUT 1 -j %s", iptablesChain),
	}

	for _, cmd := range ip6Commands {
		if err := runIPTables(cmd); err != nil {
			slog.Warn("ip6tables command failed (non-fatal)", "cmd", cmd, "error", err)
		}
	}

	k.enabled = true
	slog.Info("kill switch enabled")
	return nil
}

func (k *LinuxKillSwitch) Disable() error {
	cleanupCommands := []string{
		fmt.Sprintf("iptables -D OUTPUT -j %s", iptablesChain),
		fmt.Sprintf("iptables -F %s", iptablesChain),
		fmt.Sprintf("iptables -X %s", iptablesChain),
		fmt.Sprintf("ip6tables -D OUTPUT -j %s", iptablesChain),
		fmt.Sprintf("ip6tables -F %s", iptablesChain),
		fmt.Sprintf("ip6tables -X %s", iptablesChain),
	}

	for _, cmd := range cleanupCommands {
		runIPTables(cmd)
	}

	k.enabled = false
	slog.Info("kill switch disabled")
	return nil
}

func (k *LinuxKillSwitch) IsEnabled() bool {
	return k.enabled
}

func runIPTables(command string) error {
	parts := strings.Fields(command)
	cmd := exec.Command(parts[0], parts[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
