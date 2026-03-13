package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/FrankFMY/burrow/internal/shared"
)

type StepResult struct {
	Name    string
	Passed  bool
	Detail  string
	Latency time.Duration
}

type DiagResult struct {
	Steps []StepResult
}

func (r *DiagResult) AllPassed() bool {
	for _, s := range r.Steps {
		if !s.Passed {
			return false
		}
	}
	return true
}

const diagTimeout = 5 * time.Second

func Diagnose(invite shared.InviteData) (*DiagResult, error) {
	result := &DiagResult{}

	result.Steps = append(result.Steps, diagDNS())
	result.Steps = append(result.Steps, diagTCP(invite.Server, invite.Port))
	result.Steps = append(result.Steps, diagTLS(invite.Server, invite.Port, invite.SNI))

	if invite.CDNHost != "" {
		result.Steps = append(result.Steps, diagCDN(invite.CDNHost, invite.CDNPort))
	}

	result.Steps = append(result.Steps, diagLatency(invite.Server, invite.Port))

	return result, nil
}

func diagDNS() StepResult {
	step := StepResult{Name: "DNS Resolution"}

	start := time.Now()
	addrs, err := net.LookupHost("cloudflare.com")
	elapsed := time.Since(start)

	if err != nil {
		step.Detail = fmt.Sprintf("failed to resolve cloudflare.com: %v", err)
		return step
	}
	if len(addrs) == 0 {
		step.Detail = "resolved cloudflare.com but got no addresses"
		return step
	}

	step.Passed = true
	step.Latency = elapsed
	step.Detail = fmt.Sprintf("cloudflare.com -> %s (%s)", addrs[0], elapsed.Round(time.Millisecond))
	return step
}

func diagTCP(host string, port uint16) StepResult {
	step := StepResult{Name: "TCP Connectivity"}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, diagTimeout)
	elapsed := time.Since(start)

	if err != nil {
		step.Detail = fmt.Sprintf("cannot connect to %s: %v", addr, err)
		return step
	}
	conn.Close()

	step.Passed = true
	step.Latency = elapsed
	step.Detail = fmt.Sprintf("connected to %s (%s)", addr, elapsed.Round(time.Millisecond))
	return step
}

func diagTLS(host string, port uint16, sni string) StepResult {
	step := StepResult{Name: "TLS Handshake"}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if sni == "" {
		sni = host
	}

	dialer := &net.Dialer{Timeout: diagTimeout}
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	elapsed := time.Since(start)

	if err != nil {
		step.Detail = fmt.Sprintf("TLS handshake with %s (SNI=%s) failed: %v", addr, sni, err)
		return step
	}
	state := conn.ConnectionState()
	conn.Close()
	step.Passed = true
	step.Latency = elapsed
	step.Detail = fmt.Sprintf("TLS %s to %s (SNI=%s, cert not verified) (%s)",
		tlsVersionString(state.Version), addr, sni, elapsed.Round(time.Millisecond))
	return step
}

func diagCDN(cdnHost string, cdnPort uint16) StepResult {
	step := StepResult{Name: "CDN Reachability"}

	if cdnPort == 0 {
		cdnPort = 443
	}
	addr := net.JoinHostPort(cdnHost, fmt.Sprintf("%d", cdnPort))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, diagTimeout)
	elapsed := time.Since(start)

	if err != nil {
		step.Detail = fmt.Sprintf("cannot reach CDN %s: %v", addr, err)
		return step
	}
	conn.Close()

	step.Passed = true
	step.Latency = elapsed
	step.Detail = fmt.Sprintf("CDN %s reachable (%s)", addr, elapsed.Round(time.Millisecond))
	return step
}

func diagLatency(host string, port uint16) StepResult {
	step := StepResult{Name: "Latency (RTT)"}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	const rounds = 3
	var total time.Duration
	var success int

	for i := 0; i < rounds; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, diagTimeout)
		elapsed := time.Since(start)
		if err != nil {
			continue
		}
		conn.Close()
		total += elapsed
		success++
	}

	if success == 0 {
		step.Detail = fmt.Sprintf("all %d RTT probes to %s failed", rounds, addr)
		return step
	}

	avg := total / time.Duration(success)
	step.Passed = true
	step.Latency = avg
	step.Detail = fmt.Sprintf("avg RTT to %s: %s (%d/%d probes)", addr, avg.Round(time.Millisecond), success, rounds)
	return step
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func FormatDiagResult(r *DiagResult) string {
	var buf []byte
	buf = append(buf, "Connection Diagnostics\n"...)
	buf = append(buf, "======================\n\n"...)

	for _, s := range r.Steps {
		marker := "[FAIL]"
		if s.Passed {
			marker = "[PASS]"
		}
		buf = append(buf, fmt.Sprintf("  %s %s\n", marker, s.Name)...)
		buf = append(buf, fmt.Sprintf("        %s\n\n", s.Detail)...)
	}

	passed := 0
	for _, s := range r.Steps {
		if s.Passed {
			passed++
		}
	}
	buf = append(buf, fmt.Sprintf("Result: %d/%d checks passed\n", passed, len(r.Steps))...)

	return string(buf)
}
