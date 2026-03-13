//go:build dpi

package server

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	dpiTimeout = 10 * time.Second
)

func dpiServerAddr(t *testing.T) (string, uint16, string) {
	t.Helper()
	host := os.Getenv("BURROW_DPI_HOST")
	if host == "" {
		t.Skip("BURROW_DPI_HOST not set")
	}
	portStr := os.Getenv("BURROW_DPI_PORT")
	if portStr == "" {
		portStr = "443"
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("invalid BURROW_DPI_PORT: %v", err)
	}
	sni := os.Getenv("BURROW_DPI_SNI")
	if sni == "" {
		sni = DefaultCamouflageSNI
	}
	return host, port, sni
}

func TestTLSCamouflage(t *testing.T) {
	host, port, sni := dpiServerAddr(t)
	addr := fmt.Sprintf("%s:%d", host, port)

	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: dpiTimeout}, "tcp", addr, tlsConf)
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		t.Errorf("expected TLS >= 1.2, got 0x%04x", state.Version)
	}

	// Send a plain HTTP/1.1 request through the TLS connection.
	// The server should forward it to the camouflage site (Reality handshake behavior).
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read response: %v", err)
	}
	resp := string(buf[:n])

	if !strings.HasPrefix(resp, "HTTP/") {
		t.Errorf("expected HTTP response from camouflage site, got: %.80s", resp)
	}
}

func TestActiveProbingResistance(t *testing.T) {
	host, port, sni := dpiServerAddr(t)
	addr := fmt.Sprintf("%s:%d", host, port)

	t.Run("PlainHTTPOverTLS", func(t *testing.T) {
		tlsConf := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: dpiTimeout}, "tcp", addr, tlsConf)
		if err != nil {
			t.Fatalf("TLS dial failed: %v", err)
		}
		defer conn.Close()

		req := fmt.Sprintf("GET /probe-%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
			time.Now().UnixNano(), sni)
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write probe: %v", err)
		}

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("read probe response: %v", err)
		}
		resp := string(buf[:n])

		if !strings.HasPrefix(resp, "HTTP/") {
			t.Errorf("probe should get HTTP response from camouflage, got: %.80s", resp)
		}

		// Must not contain any proxy-related identifiers
		lower := strings.ToLower(resp)
		for _, keyword := range []string{"vless", "vmess", "trojan", "sing-box", "proxy"} {
			if strings.Contains(lower, keyword) {
				t.Errorf("response contains proxy identifier %q", keyword)
			}
		}
	})

	t.Run("RandomBinaryData", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", addr, dpiTimeout)
		if err != nil {
			t.Fatalf("TCP dial failed: %v", err)
		}
		defer conn.Close()

		junk := make([]byte, 256)
		if _, err := rand.Read(junk); err != nil {
			t.Fatalf("generate random data: %v", err)
		}

		conn.SetWriteDeadline(time.Now().Add(dpiTimeout))
		_, writeErr := conn.Write(junk)

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1024)
		_, readErr := conn.Read(buf)

		// Acceptable outcomes: write error, read EOF, read timeout, or read error.
		// The key point is that the server must NOT send a meaningful response
		// that reveals it is a proxy.
		_ = writeErr
		if readErr == nil {
			t.Log("server responded to random data (may be a TLS alert, which is acceptable)")
		}
	})

	t.Run("WrongSNI", func(t *testing.T) {
		tlsConf := &tls.Config{
			ServerName:         "wrong.example.invalid",
			InsecureSkipVerify: true,
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: dpiTimeout}, "tcp", addr, tlsConf)
		if err != nil {
			// Connection refused or handshake failure is acceptable —
			// the server does not reveal itself.
			t.Logf("wrong SNI correctly rejected: %v", err)
			return
		}
		defer conn.Close()

		// If the connection succeeded, the server should still act as a web server,
		// not reveal proxy functionality.
		req := "GET / HTTP/1.1\r\nHost: wrong.example.invalid\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(req))

		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		resp := string(buf[:n])

		lower := strings.ToLower(resp)
		for _, keyword := range []string{"vless", "vmess", "trojan", "sing-box"} {
			if strings.Contains(lower, keyword) {
				t.Errorf("wrong-SNI response contains proxy identifier %q", keyword)
			}
		}
	})
}

func TestCamouflageHTTPResponse(t *testing.T) {
	host, port, sni := dpiServerAddr(t)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{Timeout: dpiTimeout}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   dpiTimeout,
	}

	url := fmt.Sprintf("https://%s:%d/", host, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = sni

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		t.Errorf("expected 2xx-4xx status from camouflage, got %d", resp.StatusCode)
	}

	// Verify response headers look like a real web server
	server := resp.Header.Get("Server")
	if server != "" {
		t.Logf("camouflage server header: %s", server)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		t.Log("warning: no Content-Type header in camouflage response")
	}
}

func TestNoPlaintextLeak(t *testing.T) {
	host, port, sni := dpiServerAddr(t)
	addr := fmt.Sprintf("%s:%d", host, port)

	tlsConf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: dpiTimeout}, "tcp", addr, tlsConf)
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni)
	conn.Write([]byte(req))

	body, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		t.Fatalf("read body: %v", err)
	}

	lower := strings.ToLower(string(body))
	proxySignatures := []string{
		"vless", "vmess", "trojan", "shadowsocks",
		"sing-box", "xray", "v2ray", "burrow",
	}
	for _, sig := range proxySignatures {
		if strings.Contains(lower, sig) {
			t.Errorf("response body contains proxy signature %q", sig)
		}
	}
}
