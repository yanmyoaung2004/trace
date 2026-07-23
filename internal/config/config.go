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
	LLMModel     string `json:"llm_model"`
	VTAPIKey     string `json:"vt_api_key"`
	AbuseIPDBKey string `json:"abuseipdb_key"`
	OTXAPIKey    string `json:"otx_api_key"`
	WebSearchKey string `json:"web_search_key"`

	SlackWebhookURL     string `json:"slack_webhook_url,omitempty"`
	DiscordWebhookURL    string `json:"discord_webhook_url,omitempty"`
	TelegramBotToken     string `json:"telegram_bot_token,omitempty"`
	TelegramChatID       string `json:"telegram_chat_id,omitempty"`
	SMTPHost            string `json:"smtp_host,omitempty"`
	SMTPPort            int    `json:"smtp_port,omitempty"`
	SMTPUser            string `json:"smtp_user,omitempty"`
	SMTPPassword        string `json:"smtp_password,omitempty"`
	SMTPFrom            string `json:"smtp_from,omitempty"`
	EmailTo             string `json:"email_to,omitempty"`
	PagerDutyRoutingKey string `json:"pagerduty_routing_key,omitempty"`
	WebhookURL          string `json:"webhook_url,omitempty"`
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
	base := filepath.Join(home, ".trace")

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
		DBPath:     filepath.Join(base, "trace.db"),
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

	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".trace", "config.json")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, err := json.MarshalIndent(cfg, "", "  "); err == nil {
				os.MkdirAll(filepath.Dir(path), 0755)
				os.WriteFile(path, data, 0644)
			}
			return cfg, nil
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if v := os.Getenv("TRACE_DB_PATH"); v != "" {
		cfg.DBPath = v
	}
	if v := os.Getenv("TRACE_VT_API_KEY"); v != "" {
		cfg.VTAPIKey = v
	}
	if v := os.Getenv("TRACE_LLM_API_KEY"); v != "" {
		cfg.LLMAPIKey = v
	}
	if v := os.Getenv("TRACE_LLM_URL"); v != "" {
		cfg.LLMURL = v
	}
	if v := os.Getenv("TRACE_LLM_MODEL"); v != "" {
		cfg.LLMModel = v
	}
	if v := os.Getenv("TRACE_ABUSEIPDB_KEY"); v != "" {
		cfg.AbuseIPDBKey = v
	}
	if v := os.Getenv("TRACE_OTX_API_KEY"); v != "" {
		cfg.OTXAPIKey = v
	}

	return cfg, nil
}
