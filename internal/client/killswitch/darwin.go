//go:build darwin

package killswitch

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
)

const pfAnchor = "com.burrow.killswitch"

type DarwinKillSwitch struct {
	enabled     bool
	pfRulesPath string
}

func New() KillSwitch {
	return &DarwinKillSwitch{}
}

func (k *DarwinKillSwitch) getPFRulesPath() string {
	if k.pfRulesPath != "" {
		return k.pfRulesPath
	}
	if configDir, err := os.UserConfigDir(); err == nil {
		dir := filepath.Join(configDir, "burrow")
		if err := os.MkdirAll(dir, 0700); err == nil {
			k.pfRulesPath = filepath.Join(dir, "pf-rules.conf")
			return k.pfRulesPath
		}
	}
	k.pfRulesPath = "/tmp/burrow-pf-rules.conf"
	return k.pfRulesPath
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

	rulesPath := k.getPFRulesPath()
	if err := os.WriteFile(rulesPath, []byte(rules), 0600); err != nil {
		return fmt.Errorf("write pf rules: %w", err)
	}

	cmds := [][]string{
		{"pfctl", "-a", pfAnchor, "-f", rulesPath},
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
	rulesPath := k.getPFRulesPath()
	os.Remove(rulesPath)
	k.enabled = false
	slog.Info("kill switch disabled (pf)")
	return nil
}

func (k *DarwinKillSwitch) IsEnabled() bool {
	return k.enabled
}
