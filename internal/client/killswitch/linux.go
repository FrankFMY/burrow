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

type iptablesRule struct {
	binary string
	args   []string
}

func (k *LinuxKillSwitch) Enable(tunnelInterface, serverIP, dnsIP string) error {
	k.Disable()

	commands := []iptablesRule{
		{"iptables", []string{"-N", iptablesChain}},
		{"iptables", []string{"-A", iptablesChain, "-o", "lo", "-j", "ACCEPT"}},
		{"iptables", []string{"-A", iptablesChain, "-o", tunnelInterface, "-j", "ACCEPT"}},
		{"iptables", []string{"-A", iptablesChain, "-d", serverIP, "-j", "ACCEPT"}},
		{"iptables", []string{"-A", iptablesChain, "-d", "127.0.0.0/8", "-j", "ACCEPT"}},
		{"iptables", []string{"-A", iptablesChain, "-d", "10.0.0.0/8", "-j", "ACCEPT"}},
		{"iptables", []string{"-A", iptablesChain, "-d", "172.16.0.0/12", "-j", "ACCEPT"}},
		{"iptables", []string{"-A", iptablesChain, "-d", "192.168.0.0/16", "-j", "ACCEPT"}},
		{"iptables", []string{"-A", iptablesChain, "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"}},
		{"iptables", []string{"-A", iptablesChain, "-j", "DROP"}},
		{"iptables", []string{"-I", "OUTPUT", "1", "-j", iptablesChain}},
	}

	for _, rule := range commands {
		if err := runIPTables(rule); err != nil {
			k.Disable()
			return fmt.Errorf("enable kill switch: %w (cmd: %s %s)", err, rule.binary, strings.Join(rule.args, " "))
		}
	}

	ip6Commands := []iptablesRule{
		{"ip6tables", []string{"-N", iptablesChain}},
		{"ip6tables", []string{"-A", iptablesChain, "-o", "lo", "-j", "ACCEPT"}},
		{"ip6tables", []string{"-A", iptablesChain, "-o", tunnelInterface, "-j", "ACCEPT"}},
		{"ip6tables", []string{"-A", iptablesChain, "-d", "::1/128", "-j", "ACCEPT"}},
		{"ip6tables", []string{"-A", iptablesChain, "-j", "DROP"}},
		{"ip6tables", []string{"-I", "OUTPUT", "1", "-j", iptablesChain}},
	}

	for _, rule := range ip6Commands {
		if err := runIPTables(rule); err != nil {
			slog.Warn("ip6tables command failed (non-fatal)", "cmd", rule.binary+" "+strings.Join(rule.args, " "), "error", err)
		}
	}

	k.enabled = true
	slog.Info("kill switch enabled")
	return nil
}

func (k *LinuxKillSwitch) Disable() error {
	cleanupCommands := []iptablesRule{
		{"iptables", []string{"-D", "OUTPUT", "-j", iptablesChain}},
		{"iptables", []string{"-F", iptablesChain}},
		{"iptables", []string{"-X", iptablesChain}},
		{"ip6tables", []string{"-D", "OUTPUT", "-j", iptablesChain}},
		{"ip6tables", []string{"-F", iptablesChain}},
		{"ip6tables", []string{"-X", iptablesChain}},
	}

	for _, rule := range cleanupCommands {
		runIPTables(rule)
	}

	k.enabled = false
	slog.Info("kill switch disabled")
	return nil
}

func (k *LinuxKillSwitch) IsEnabled() bool {
	return k.enabled
}

func runIPTables(rule iptablesRule) error {
	cmd := exec.Command(rule.binary, rule.args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
