//go:build darwin

package killswitch

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

const pfAnchor = "com.burrow.killswitch"
const pfRulesPath = "/tmp/burrow-pf-rules.conf"

type DarwinKillSwitch struct {
	enabled bool
}

func New() KillSwitch {
	return &DarwinKillSwitch{}
}

func (k *DarwinKillSwitch) Enable(tunnelInterface, serverIP, dnsIP string) error {
	k.Disable()

	rules := fmt.Sprintf(`
block drop out all
pass out on lo0 all
pass out on %s all
pass out proto {tcp, udp} to %s
pass out proto udp to any port 67:68
pass out to 127.0.0.0/8
pass out to 10.0.0.0/8
pass out to 172.16.0.0/12
pass out to 192.168.0.0/16
`, tunnelInterface, serverIP)

	if err := os.WriteFile(pfRulesPath, []byte(rules), 0600); err != nil {
		return fmt.Errorf("write pf rules: %w", err)
	}

	cmds := [][]string{
		{"pfctl", "-a", pfAnchor, "-f", pfRulesPath},
		{"pfctl", "-e"},
	}

	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("pf command failed", "cmd", args, "output", string(output), "error", err)
		}
	}

	k.enabled = true
	slog.Info("kill switch enabled (pf)")
	return nil
}

func (k *DarwinKillSwitch) Disable() error {
	exec.Command("pfctl", "-a", pfAnchor, "-F", "all").Run()
	os.Remove(pfRulesPath)
	k.enabled = false
	slog.Info("kill switch disabled (pf)")
	return nil
}

func (k *DarwinKillSwitch) IsEnabled() bool {
	return k.enabled
}
