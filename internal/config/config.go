package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	DBPath   string `json:"db_path"`
	DataDir  string `json:"data_dir"`
	LogDir   string `json:"log_dir"`
	Playbook string `json:"playbook_dir"`
	IntelDir string `json:"intel_dir"`

	Telemetry TelemetryConfig `json:"telemetry"`
	SIEM      SIEMConfig      `json:"siem"`
	Server    ServerConfig    `json:"server"`

	LLMProvider  string `json:"llm_provider"`
	LLMURL       string `json:"llm_url"`
	LLMAPIKey    string `json:"llm_api_key"`
	VTAPIKey     string `json:"vt_api_key"`
	AbuseIPDBKey string `json:"abuseipdb_key"`
	OTXAPIKey    string `json:"otx_api_key"`
	WebSearchKey string `json:"web_search_key"`
}

type TelemetryConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url,omitempty"`
}

type SIEMConfig struct {
	Enabled  bool   `json:"enabled"`
	LogDir   string `json:"log_dir"`
	SyslogAddr string `json:"syslog_addr"`
}

type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type ServerConfig struct {
	Enabled  bool      `json:"enabled"`
	GRPCAddr string    `json:"grpc_addr"`
	HTTPAddr string    `json:"http_addr"`
	TLS      TLSConfig `json:"tls"`
}

func repoDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	if fi, err := os.Stat(filepath.Join(dir, "playbooks")); err == nil && fi.IsDir() {
		return dir
	}
	if fi, err := os.Stat(filepath.Join(dir, "intel")); err == nil && fi.IsDir() {
		return dir
	}
	return ""
}

func Default() *Config {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".innoigniter")

	playbookDir := filepath.Join(base, "playbooks")
	intelDir := filepath.Join(base, "intel")

	if rd := repoDir(); rd != "" {
		if _, err := os.Stat(playbookDir); os.IsNotExist(err) {
			playbookDir = filepath.Join(rd, "playbooks")
		}
		if _, err := os.Stat(intelDir); os.IsNotExist(err) {
			intelDir = filepath.Join(rd, "intel")
		}
	}

	return &Config{
		DBPath:     filepath.Join(base, "innoigniter.db"),
		DataDir:    filepath.Join(base, "data"),
		LogDir:     filepath.Join(base, "logs"),
		Playbook:   playbookDir,
		IntelDir:   intelDir,
		LLMProvider: "openai",
		SIEM: SIEMConfig{
			SyslogAddr: ":514",
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	if v := os.Getenv("INNO_DB_PATH"); v != "" {
		cfg.DBPath = v
	}
	if v := os.Getenv("INNO_VT_API_KEY"); v != "" {
		cfg.VTAPIKey = v
	}
	if v := os.Getenv("INNO_LLM_API_KEY"); v != "" {
		cfg.LLMAPIKey = v
	}
	if v := os.Getenv("INNO_LLM_URL"); v != "" {
		cfg.LLMURL = v
	}
	if v := os.Getenv("INNO_ABUSEIPDB_KEY"); v != "" {
		cfg.AbuseIPDBKey = v
	}
	if v := os.Getenv("INNO_OTX_API_KEY"); v != "" {
		cfg.OTXAPIKey = v
	}

	return cfg, nil
}
