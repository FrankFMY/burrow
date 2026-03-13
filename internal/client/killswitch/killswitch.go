package killswitch

import "errors"

var ErrNotSupported = errors.New("kill switch not supported on this platform")

type KillSwitch interface {
	Enable(tunnelInterface string, serverIP string, dnsIP string) error
	Disable() error
	IsEnabled() bool
}
