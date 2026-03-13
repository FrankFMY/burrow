package server

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzLoadConfig(f *testing.F) {
	f.Add([]byte(`{"listen_port":443,"api_port":8080,"camouflage_sni":"www.microsoft.com"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"listen_port":0,"api_port":0}`))
	f.Add([]byte(`{"users":[{"name":"test","uuid":"123"}]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "fuzz.json")
		if err := os.WriteFile(cfgPath, data, 0600); err != nil {
			t.Fatalf("write fuzz file: %v", err)
		}
		cfg, err := LoadConfig(cfgPath)
		if err != nil {
			return
		}
		outPath := filepath.Join(dir, "out.json")
		if err := SaveConfig(outPath, cfg); err != nil {
			t.Fatalf("SaveConfig failed on valid parsed config: %v", err)
		}
		cfg2, err := LoadConfig(outPath)
		if err != nil {
			t.Fatalf("LoadConfig failed on re-saved config: %v", err)
		}
		if cfg.ListenPort != cfg2.ListenPort {
			t.Errorf("listen_port mismatch after round trip: %d vs %d", cfg.ListenPort, cfg2.ListenPort)
		}
	})
}
