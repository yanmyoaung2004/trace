package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yanmyoaung2004/innoigniter-ai/internal/config"
)

func TestDefault(t *testing.T) {
	cfg := config.Default()
	if cfg.DBPath == "" {
		t.Fatal("DBPath should not be empty")
	}
	if cfg.LLMProvider != "openai" {
		t.Fatalf("expected openai, got %s", cfg.LLMProvider)
	}
}

func TestLoadNoFileReturnsDefault(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("cfg should not be nil")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"db_path": "/tmp/test.db", "llm_provider": "ollama"}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.DBPath != "/tmp/test.db" {
		t.Fatalf("expected /tmp/test.db, got %s", cfg.DBPath)
	}
	if cfg.LLMProvider != "ollama" {
		t.Fatalf("expected ollama, got %s", cfg.LLMProvider)
	}
}

func TestEnvOverride(t *testing.T) {
	os.Setenv("INNO_DB_PATH", "/env/test.db")
	os.Setenv("INNO_VT_API_KEY", "vtkey-123")
	defer os.Unsetenv("INNO_DB_PATH")
	defer os.Unsetenv("INNO_VT_API_KEY")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.DBPath != "/env/test.db" {
		t.Fatalf("expected /env/test.db, got %s", cfg.DBPath)
	}
	if cfg.VTAPIKey != "vtkey-123" {
		t.Fatalf("expected vtkey-123, got %s", cfg.VTAPIKey)
	}
}

func TestFileThenEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"db_path": "/file/db.db", "vt_api_key": "file-key"}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	os.Setenv("INNO_DB_PATH", "/env/db.db")
	defer os.Unsetenv("INNO_DB_PATH")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.DBPath != "/env/db.db" {
		t.Fatalf("expected env override /env/db.db, got %s", cfg.DBPath)
	}
	if cfg.VTAPIKey != "file-key" {
		t.Fatalf("expected file-key, got %s", cfg.VTAPIKey)
	}
}

func TestLoadBadFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "nope.json")
	_, err := config.Load(bad)
	if err == nil {
		t.Fatal("expected error loading non-existent file")
	}
}
