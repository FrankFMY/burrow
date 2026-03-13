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

func (k *WindowsKillSwitch) Enable(tunnelInterface, serverIP, dnsIP string) error {
	k.Disable()

	rules := []struct {
		name string
		args string
	}{
		{
			name: firewallRulePrefix + "_BlockAll",
			args: fmt.Sprintf(`netsh advfirewall firewall add rule name="%s_BlockAll" dir=out action=block enable=yes`, firewallRulePrefix),
		},
		{
			name: firewallRulePrefix + "_AllowServer",
			args: fmt.Sprintf(`netsh advfirewall firewall add rule name="%s_AllowServer" dir=out action=allow remoteip=%s enable=yes`, firewallRulePrefix, serverIP),
		},
		{
			name: firewallRulePrefix + "_AllowLoopback",
			args: fmt.Sprintf(`netsh advfirewall firewall add rule name="%s_AllowLoopback" dir=out action=allow remoteip=127.0.0.0/8 enable=yes`, firewallRulePrefix),
		},
		{
			name: firewallRulePrefix + "_AllowLAN1",
			args: fmt.Sprintf(`netsh advfirewall firewall add rule name="%s_AllowLAN1" dir=out action=allow remoteip=10.0.0.0/8 enable=yes`, firewallRulePrefix),
		},
		{
			name: firewallRulePrefix + "_AllowLAN2",
			args: fmt.Sprintf(`netsh advfirewall firewall add rule name="%s_AllowLAN2" dir=out action=allow remoteip=172.16.0.0/12 enable=yes`, firewallRulePrefix),
		},
		{
			name: firewallRulePrefix + "_AllowLAN3",
			args: fmt.Sprintf(`netsh advfirewall firewall add rule name="%s_AllowLAN3" dir=out action=allow remoteip=192.168.0.0/16 enable=yes`, firewallRulePrefix),
		},
		{
			name: firewallRulePrefix + "_AllowDHCP",
			args: fmt.Sprintf(`netsh advfirewall firewall add rule name="%s_AllowDHCP" dir=out action=allow protocol=udp remoteport=67-68 enable=yes`, firewallRulePrefix),
		},
	}

	for _, rule := range rules {
		parts := strings.Fields(rule.args)
		cmd := exec.Command(parts[0], parts[1:]...)
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
