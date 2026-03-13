//go:build windows

package killswitch

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

const firewallRulePrefix = "BurrowKillSwitch"

type WindowsKillSwitch struct {
	enabled bool
}

func New() KillSwitch {
	return &WindowsKillSwitch{}
}

type netshRule struct {
	name string
	args []string
}

func (k *WindowsKillSwitch) Enable(tunnelInterface, serverIP, dnsIP string) error {
	k.Disable()

	rules := []netshRule{
		{
			name: firewallRulePrefix + "_BlockAll",
			args: []string{"advfirewall", "firewall", "add", "rule",
				fmt.Sprintf("name=%s_BlockAll", firewallRulePrefix),
				"dir=out", "action=block", "enable=yes"},
		},
		{
			name: firewallRulePrefix + "_AllowServer",
			args: []string{"advfirewall", "firewall", "add", "rule",
				fmt.Sprintf("name=%s_AllowServer", firewallRulePrefix),
				"dir=out", "action=allow",
				fmt.Sprintf("remoteip=%s", serverIP), "enable=yes"},
		},
		{
			name: firewallRulePrefix + "_AllowLoopback",
			args: []string{"advfirewall", "firewall", "add", "rule",
				fmt.Sprintf("name=%s_AllowLoopback", firewallRulePrefix),
				"dir=out", "action=allow", "remoteip=127.0.0.0/8", "enable=yes"},
		},
		{
			name: firewallRulePrefix + "_AllowLAN1",
			args: []string{"advfirewall", "firewall", "add", "rule",
				fmt.Sprintf("name=%s_AllowLAN1", firewallRulePrefix),
				"dir=out", "action=allow", "remoteip=10.0.0.0/8", "enable=yes"},
		},
		{
			name: firewallRulePrefix + "_AllowLAN2",
			args: []string{"advfirewall", "firewall", "add", "rule",
				fmt.Sprintf("name=%s_AllowLAN2", firewallRulePrefix),
				"dir=out", "action=allow", "remoteip=172.16.0.0/12", "enable=yes"},
		},
		{
			name: firewallRulePrefix + "_AllowLAN3",
			args: []string{"advfirewall", "firewall", "add", "rule",
				fmt.Sprintf("name=%s_AllowLAN3", firewallRulePrefix),
				"dir=out", "action=allow", "remoteip=192.168.0.0/16", "enable=yes"},
		},
		{
			name: firewallRulePrefix + "_AllowDHCP",
			args: []string{"advfirewall", "firewall", "add", "rule",
				fmt.Sprintf("name=%s_AllowDHCP", firewallRulePrefix),
				"dir=out", "action=allow", "protocol=udp", "remoteport=67-68", "enable=yes"},
		},
	}

	for _, rule := range rules {
		cmd := exec.Command("netsh", rule.args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			k.Disable()
			return fmt.Errorf("enable kill switch rule %s: %w (%s)", rule.name, err, strings.TrimSpace(string(output)))
		}
	}

	k.enabled = true
	slog.Info("kill switch enabled (Windows Firewall)")
	return nil
}

func (k *WindowsKillSwitch) Disable() error {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s_BlockAll", firewallRulePrefix))
	cmd.Run()

	for _, suffix := range []string{"AllowServer", "AllowLoopback", "AllowLAN1", "AllowLAN2", "AllowLAN3", "AllowDHCP"} {
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			fmt.Sprintf("name=%s_%s", firewallRulePrefix, suffix))
		cmd.Run()
	}

	k.enabled = false
	slog.Info("kill switch disabled (Windows Firewall)")
	return nil
}

func (k *WindowsKillSwitch) IsEnabled() bool {
	return k.enabled
}
