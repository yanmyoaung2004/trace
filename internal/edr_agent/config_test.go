package edr_agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ServerURL != "https://127.0.0.1:8080" {
		t.Errorf("expected default server URL, got %s", cfg.ServerURL)
	}
	if cfg.PollInterval == 0 {
		t.Error("poll interval should be non-zero")
	}
	if cfg.HeartbeatInterval == 0 {
		t.Error("heartbeat interval should be non-zero")
	}
	if cfg.MaxBatchSize <= 0 {
		t.Error("max batch size should be positive")
	}
	if cfg.EventQueueSize <= 0 {
		t.Error("event queue size should be positive")
	}
	if !cfg.MonitorProcess {
		t.Error("process monitoring should be enabled by default")
	}
}

func TestConfigSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	cfg.ServerURL = "https://trace.example.com:8443"
	cfg.APIKey = "test-key-12345"
	cfg.MonitorProcess = false
	cfg.MonitorFile = true
	cfg.MaxBatchSize = 200

	if err := cfg.Save(path); err != nil {
		t.Fatalf("save config: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("config file was not created")
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if loaded.ServerURL != "https://trace.example.com:8443" {
		t.Errorf("server URL mismatch: got %s", loaded.ServerURL)
	}
	if loaded.APIKey != "test-key-12345" {
		t.Errorf("API key mismatch: got %s", loaded.APIKey)
	}
	if loaded.MonitorProcess {
		t.Error("MonitorProcess should be false")
	}
	if !loaded.MonitorFile {
		t.Error("MonitorFile should be true")
	}
	if loaded.MaxBatchSize != 200 {
		t.Errorf("MaxBatchSize mismatch: got %d", loaded.MaxBatchSize)
	}
}

func TestConfigLoadMissing(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/config.json")
	if err != nil {
		t.Fatalf("load missing config: %v", err)
	}
	if cfg == nil {
		t.Fatal("should return default config")
	}
}

func TestConfigSaveDirCreation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dirs")
	path := filepath.Join(dir, "agent.json")

	cfg := DefaultConfig()
	if err := cfg.Save(path); err != nil {
		t.Fatalf("save config with nested dirs: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("config file was not created in nested dirs")
	}
}
