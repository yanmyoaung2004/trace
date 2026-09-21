package config

// Single canonical config loader.
//
// Precedence (highest wins): TRACE_* env (or *_FILE) > flag overrides >
// file > DB(remote) > default. See ApplyFlags / MergeRemote. Run
// `trace config check` and `trace config dump --effective` to inspect.
//
// No new external dependencies. Secrets never logged by this package.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/yanmyoaung2004/trace/internal/siem"
)

const (
	// DefaultServerAddr is the canonical single server address (:8080 per
	// fleet alignment; StorageFixer/ServerTrustFixer/SupplyDeployFixer ack).
	DefaultServerAddr = ":8080"
)

// SIEMConfig is the single canonical SIEM config type. The old central
// duplicate is gone: this is an alias for siem.SIEMConfig, so flags and
// file both override the same struct. Old file keys (log_dir, syslog_addr)
// are migrated with a warning by Load (see migrateSIEMKeys).
type SIEMConfig = siem.SIEMConfig

type TelemetryConfig struct {
	Enabled bool   `json:"enabled" env:"TRACE_TELEMETRY_ENABLED"`
	URL     string `json:"url,omitempty" env:"TRACE_TELEMETRY_URL"`
}

type TSEConfig struct {
	Enabled          bool   `json:"tse_enabled" env:"TRACE_TSE_ENABLED"`
	NodeRole         string `json:"tse_node_role,omitempty" env:"TRACE_TSE_NODE_ROLE"`
	StoragePath      string `json:"tse_storage_path" env:"TRACE_TSE_STORAGE_PATH"`
	Compression      string `json:"tse_compression" env:"TRACE_TSE_COMPRESSION"`
	CompressionLevel int    `json:"tse_compression_level" env:"TRACE_TSE_COMPRESSION_LEVEL"`
	RowGroupSize     int    `json:"tse_row_group_size" env:"TRACE_TSE_ROW_GROUP_SIZE"`
	HotWindow        string `json:"tse_hot_window" env:"TRACE_TSE_HOT_WINDOW"`
	FlushInterval    string `json:"tse_flush_interval" env:"TRACE_TSE_FLUSH_INTERVAL"`
	ColdTTL          string `json:"tse_cold_ttl" env:"TRACE_TSE_COLD_TTL"`
	AdminToken       string `json:"tse_admin_token,omitempty" env:"TRACE_TSE_ADMIN_TOKEN" fileenv:"TRACE_TSE_ADMIN_TOKEN_FILE"`
	S3Bucket         string `json:"tse_s3_bucket,omitempty" env:"TRACE_S3_BUCKET"`
	S3Endpoint       string `json:"tse_s3_endpoint,omitempty" env:"TRACE_S3_ENDPOINT"`
	S3Region         string `json:"tse_s3_region,omitempty" env:"TRACE_S3_REGION"`
	S3UseSSL         bool   `json:"tse_s3_usessl" env:"TRACE_S3_USE_SSL"`
	S3AccessKey      string `json:"tse_s3_access_key,omitempty" env:"TRACE_S3_ACCESS_KEY" fileenv:"TRACE_S3_ACCESS_KEY_FILE"`
	S3SecretKey      string `json:"tse_s3_secret_key,omitempty" env:"TRACE_S3_SECRET_KEY" fileenv:"TRACE_S3_SECRET_KEY_FILE"`

	BackupEnabled      bool   `json:"tse_backup_enabled,omitempty" env:"TRACE_TSE_BACKUP_ENABLED"`
	BackupInterval     string `json:"tse_backup_interval,omitempty" env:"TRACE_TSE_BACKUP_INTERVAL"`
	BackupDir          string `json:"tse_backup_dir,omitempty" env:"TRACE_TSE_BACKUP_DIR"`
	BackupMaxRetention int    `json:"tse_backup_max_retention,omitempty" env:"TRACE_TSE_BACKUP_MAX_RETENTION"`

	ShardCount int `json:"tse_shard_count,omitempty" env:"TRACE_TSE_SHARD_COUNT"`
}

type TLSConfig struct {
	Enabled  bool   `json:"enabled" env:"TRACE_TLS_ENABLED"`
	CertFile string `json:"cert_file" env:"TRACE_TLS_CERT"`
	KeyFile  string `json:"key_file" env:"TRACE_TLS_KEY"`
}

type ServerConfig struct {
	Enabled bool      `json:"enabled" env:"TRACE_SERVER_ENABLED"`
	Addr    string    `json:"addr" env:"TRACE_HTTP_ADDR,TRACE_SERVER_ADDR"`
	HTTPAddr string   `json:"http_addr,omitempty"`
	GRPCAddr string   `json:"grpc_addr,omitempty"`
	TLS         TLSConfig `json:"tls"`
	DatabaseURL string    `json:"database_url,omitempty" env:"TRACE_DATABASE_URL" fileenv:"TRACE_DATABASE_URL_FILE"`
}

// EffectiveAddr returns the single canonical listen address.
func (s *ServerConfig) EffectiveAddr() string {
	if s.Addr != "" {
		return s.Addr
	}
	if s.HTTPAddr != "" {
		return s.HTTPAddr
	}
	return DefaultServerAddr
}

// ResponseConfig holds response trust-boundary tunables (HIGH: quarantine
// path is a trust boundary).
type ResponseConfig struct {
	QuarantineDir   string `json:"quarantine_dir" env:"TRACE_RESPONSE_QUARANTINE_DIR"`
	Timeout         string `json:"timeout" env:"TRACE_RESPONSE_TIMEOUT"`
	RunScriptEnabled bool  `json:"run_script_enabled" env:"TRACE_RESPONSE_RUN_SCRIPT_ENABLED"`
}

// LLMConfig carries planner tunables (externalized B-literals).
type LLMConfig struct {
	Timeout     string `json:"timeout" env:"TRACE_LLM_TIMEOUT"`
	Temperature float64 `json:"temperature" env:"TRACE_LLM_TEMPERATURE"`
	MaxTokens   int    `json:"max_tokens" env:"TRACE_LLM_MAX_TOKENS"`
	BudgetCalls int    `json:"budget_calls_per_min" env:"TRACE_LLM_BUDGET_CALLS"`
	CacheTTL    string `json:"cache_ttl" env:"TRACE_LLM_CACHE_TTL"`
}

// UpdateConfig carries OTA update trust roots.
type UpdateConfig struct {
	BaseURL    string `json:"base_url,omitempty" env:"TRACE_UPDATE_BASE_URL"`
	SigningKey string `json:"signing_key,omitempty" env:"TRACE_UPDATE_SIGNING_KEY" fileenv:"TRACE_UPDATE_SIGNING_KEY_FILE"`
}

type Config struct {
	DBPath   string `json:"db_path" env:"TRACE_DB_PATH"`
	DataDir  string `json:"data_dir" env:"TRACE_DATA_DIR"`
	LogDir   string `json:"log_dir" env:"TRACE_LOG_DIR"`
	Playbook string `json:"playbook_dir" env:"TRACE_PLAYBOOK_DIR"`
	IntelDir string `json:"intel_dir" env:"TRACE_INTEL_DIR"`

	Telemetry TelemetryConfig `json:"telemetry"`
	SIEM      SIEMConfig      `json:"siem"`
	Server    ServerConfig    `json:"server"`
	TSE       TSEConfig       `json:"tse"`
	LLM       LLMConfig       `json:"llm"`
	Response  ResponseConfig  `json:"response"`
	Update    UpdateConfig    `json:"update"`

	LLMProvider  string `json:"llm_provider" env:"TRACE_LLM_PROVIDER"`
	LLMURL       string `json:"llm_url" env:"TRACE_LLM_URL" fileenv:"TRACE_LLM_URL_FILE"`
	LLMAPIKey    string `json:"llm_api_key" env:"TRACE_LLM_API_KEY" fileenv:"TRACE_LLM_API_KEY_FILE"`
	LLMModel     string `json:"llm_model" env:"TRACE_LLM_MODEL"`
	VTAPIKey     string `json:"vt_api_key" env:"TRACE_VT_API_KEY" fileenv:"TRACE_VT_API_KEY_FILE"`
	AbuseIPDBKey string `json:"abuseipdb_key" env:"TRACE_ABUSEIPDB_KEY" fileenv:"TRACE_ABUSEIPDB_KEY_FILE"`
	OTXAPIKey    string `json:"otx_api_key" env:"TRACE_OTX_API_KEY" fileenv:"TRACE_OTX_API_KEY_FILE"`
	WebSearchKey string `json:"web_search_key" env:"TRACE_WEB_SEARCH_KEY" fileenv:"TRACE_WEB_SEARCH_KEY_FILE"`

	SlackWebhookURL     string `json:"slack_webhook_url,omitempty" env:"TRACE_SLACK_WEBHOOK_URL" fileenv:"TRACE_SLACK_WEBHOOK_URL_FILE"`
	DiscordWebhookURL   string `json:"discord_webhook_url,omitempty" env:"TRACE_DISCORD_WEBHOOK_URL" fileenv:"TRACE_DISCORD_WEBHOOK_URL_FILE"`
	TelegramBotToken    string `json:"telegram_bot_token,omitempty" env:"TRACE_TELEGRAM_BOT_TOKEN" fileenv:"TRACE_TELEGRAM_BOT_TOKEN_FILE"`
	TelegramChatID      string `json:"telegram_chat_id,omitempty" env:"TRACE_TELEGRAM_CHAT_ID"`
	SMTPHost            string `json:"smtp_host,omitempty" env:"TRACE_SMTP_HOST"`
	SMTPPort            int    `json:"smtp_port,omitempty" env:"TRACE_SMTP_PORT"`
	SMTPUser            string `json:"smtp_user,omitempty" env:"TRACE_SMTP_USER"`
	SMTPPassword        string `json:"smtp_password,omitempty" env:"TRACE_SMTP_PASSWORD" fileenv:"TRACE_SMTP_PASSWORD_FILE"`
	SMTPFrom            string `json:"smtp_from,omitempty" env:"TRACE_SMTP_FROM"`
	EmailTo             string `json:"email_to,omitempty" env:"TRACE_EMAIL_TO"`
	PagerDutyRoutingKey string `json:"pagerduty_routing_key,omitempty" env:"TRACE_PAGERDUTY_ROUTING_KEY" fileenv:"TRACE_PAGERDUTY_ROUTING_KEY_FILE"`
	WebhookURL          string `json:"webhook_url,omitempty" env:"TRACE_WEBHOOK_URL" fileenv:"TRACE_WEBHOOK_URL_FILE"`
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

	qDir, _ := os.MkdirTemp("", "")
	_ = os.Remove(qDir)
	qDir = filepath.Join(os.TempDir(), "trace-quarantine")

	return &Config{
		DBPath:     filepath.Join(base, "trace.db"),
		DataDir:    filepath.Join(base, "data"),
		LogDir:     filepath.Join(base, "logs"),
		Playbook:   playbookDir,
		IntelDir:   intelDir,
		LLMProvider: "openai",
		TSE: TSEConfig{
			Enabled:       false,
			StoragePath:   filepath.Join(base, "tse"),
			Compression:   "zstd",
			HotWindow:     "2h",
			FlushInterval: "30s",
		},
		SIEM: SIEMConfig{
			PollInterval: "5s",
		},
		Server: ServerConfig{
			Addr: DefaultServerAddr,
		},
		LLM: LLMConfig{
			Timeout:     "30s",
			Temperature: 0.1,
			MaxTokens:   300,
			BudgetCalls: 60,
			CacheTTL:    "10m",
		},
		Response: ResponseConfig{
			QuarantineDir:    qDir,
			Timeout:          "30s",
			RunScriptEnabled: false,
		},
	}
}

// Save writes the config to the given path with 0600 perms (dir 0700:
// secrets hygiene — config carries API keys and webhooks).
func Save(path string, cfg *Config) error {
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".trace", "config.json")
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// HasAnyNotifier returns true if at least one notification channel is configured.
func (c *Config) HasAnyNotifier() bool {
	return c.SlackWebhookURL != "" ||
		c.DiscordWebhookURL != "" ||
		c.TelegramBotToken != "" ||
		c.SMTPHost != "" ||
		c.PagerDutyRoutingKey != "" ||
		c.WebhookURL != ""
}

// Validate checks ranges and formats. Called by Load and `config check`.
func (c *Config) Validate() error {
	if c.SMTPPort < 0 || c.SMTPPort > 65535 {
		return fmt.Errorf("smtp_port %d out of range 0-65535", c.SMTPPort)
	}
	for _, d := range []struct {
		name, val string
	}{
		{"tse_hot_window", c.TSE.HotWindow},
		{"tse_flush_interval", c.TSE.FlushInterval},
		{"tse_cold_ttl", c.TSE.ColdTTL},
		{"tse_backup_interval", c.TSE.BackupInterval},
		{"llm.timeout", c.LLM.Timeout},
		{"llm.cache_ttl", c.LLM.CacheTTL},
		{"response.timeout", c.Response.Timeout},
		{"siem.poll_interval", c.SIEM.PollInterval},
	} {
		if d.val == "" {
			continue
		}
		if _, err := time.ParseDuration(d.val); err != nil {
			return fmt.Errorf("%s: invalid duration %q: %w", d.name, d.val, err)
		}
	}
	switch c.TSE.Compression {
	case "", "zstd", "snappy", "gzip", "lz4", "none":
	default:
		return fmt.Errorf("tse_compression %q must be zstd|snappy|gzip|lz4|none", c.TSE.Compression)
	}
	if c.TSE.CompressionLevel < 0 {
		return fmt.Errorf("tse_compression_level must be >= 0")
	}
	if c.TSE.RowGroupSize < 0 {
		return fmt.Errorf("tse_row_group_size must be >= 0")
	}
	if c.TSE.ShardCount < 0 || c.TSE.ShardCount > 64 {
		return fmt.Errorf("tse_shard_count %d out of range 0-64", c.TSE.ShardCount)
	}
	if c.TSE.BackupMaxRetention < 0 {
		return fmt.Errorf("tse_backup_max_retention must be >= 0")
	}
	switch c.TSE.NodeRole {
	case "", "leader", "follower", "auto":
	default:
		return fmt.Errorf("tse_node_role %q must be leader|follower|auto", c.TSE.NodeRole)
	}
	if c.LLM.Temperature < 0 || c.LLM.Temperature > 2 {
		return fmt.Errorf("llm.temperature %v out of range 0-2", c.LLM.Temperature)
	}
	if c.LLM.MaxTokens < 0 || c.LLM.MaxTokens > 128000 {
		return fmt.Errorf("llm.max_tokens %d out of range 0-128000", c.LLM.MaxTokens)
	}
	if c.LLM.BudgetCalls < 0 {
		return fmt.Errorf("llm.budget_calls_per_min must be >= 0")
	}
	if c.SIEM.PollInterval != "" {
		if _, err := time.ParseDuration(c.SIEM.PollInterval); err != nil {
			return fmt.Errorf("siem.poll_interval: %w", err)
		}
	}
	if addr := c.Server.EffectiveAddr(); addr == "" {
		return fmt.Errorf("server addr must not be empty")
	}
	return nil
}

// CheckResult is the output of Check.
type CheckResult struct {
	Warnings []string `json:"warnings"`
	Effective *Config `json:"-"`
}

// Check validates and returns non-fatal warnings (unknown keys observed at
// load are appended by Load via pendingWarnings).
func (c *Config) Check() CheckResult {
	res := CheckResult{Effective: c}
	res.Warnings = append(res.Warnings, pendingWarningsFor(c)...)
	if err := c.Validate(); err != nil {
		res.Warnings = append(res.Warnings, "invalid: "+err.Error())
	}
	return res
}

// DumpEffective redacts secrets before printing.
func (c *Config) DumpEffective() ([]byte, error) {
	cp := *c
	redactSecrets(reflect.ValueOf(&cp).Elem())
	return json.MarshalIndent(&cp, "", "  ")
}

func redactSecrets(v reflect.Value) {
	t := v.Type()
	for i := range v.NumField() {
		f := v.Field(i)
		sf := t.Field(i)
		if f.Kind() == reflect.Struct {
			redactSecrets(f)
			continue
		}
		if f.Kind() != reflect.String {
			continue
		}
		name := strings.ToLower(sf.Name)
		if strings.Contains(name, "key") || strings.Contains(name, "token") ||
			strings.Contains(name, "secret") || strings.Contains(name, "webhook") ||
			strings.Contains(name, "password") {
			if f.String() != "" {
				f.SetString("***redacted***")
			}
		}
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()

	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".trace", "config.json")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := Save(path, cfg); err != nil {
				return cfg, nil // best effort; defaults still usable
			}
			return cfg, nil
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	// Unknown keys warn (not silent ignore, not hard fail): decode into a
	// map first, then decode into cfg. Record warnings for Check().
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	migrateTopLevelKeys(raw)
	warns := unknownKeyWarnings(raw, cfg)
	rememberWarnings(cfg, warns)
	for _, w := range warns {
		log.Printf("[config] warn: %s", w)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	// NOTE: intentionally NOT DisallowUnknownFields here; unknown keys warn
	// above and `trace config migrate` rewrites them.
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// Re-decode the migrated map so old siem keys still apply.
	if migrated, ok := migratedSIEM(raw); ok {
		mergeSIEM(cfg, migrated)
	}

	applyEnv(cfg)
	normalize(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ApplyFlags applies cobra flag overrides (flag > file). Callers pass only
// flags the user explicitly set. Unknown flag names are ignored.
func (c *Config) ApplyFlags(flags map[string]string) {
	for k, v := range flags {
		if v == "" {
			continue
		}
		switch k {
		case "tse-storage-path":
			c.TSE.StoragePath = v
		case "tse-node-role":
			c.TSE.NodeRole = v
		case "tse-compression":
			c.TSE.Compression = v
		case "syslog-addr":
			c.SIEM.SyslogUDPAddr = v
			c.SIEM.SyslogTCPAddr = v
		case "server-addr":
			c.Server.Addr = v
		case "llm-provider":
			c.LLMProvider = v
		case "llm-url":
			c.LLMURL = v
		case "llm-model":
			c.LLMModel = v
		}
	}
}

// MergeRemote merges DB(remote) values under file: only keys that are still at their default are overwritten.
// get returns (value, ok).
func (c *Config) MergeRemote(get func(key string) (string, bool)) {
	d := Default()
	setIfDefault := func(cur *string, def string, key string) {
		if *cur != def {
			return
		}
		if v, ok := get(key); ok && v != "" {
			*cur = v
		}
	}
	setIfDefault(&c.LLMProvider, d.LLMProvider, "llm_provider")
	setIfDefault(&c.LLMURL, d.LLMURL, "llm_url")
	setIfDefault(&c.LLMModel, d.LLMModel, "llm_model")
	setIfDefault(&c.Server.Addr, d.Server.Addr, "server_addr")
}

// Migrate rewrites deprecated keys in the file at path and saves with 0600.
// Returns the list of applied migrations.
func Migrate(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var applied []string
	if siemRaw, ok := raw["siem"].(map[string]any); ok {
		if v, ok := siemRaw["log_dir"]; ok {
			siemRaw["log_dirs"] = []any{v}
			delete(siemRaw, "log_dir")
			applied = append(applied, "siem.log_dir -> siem.log_dirs")
		}
		if v, ok := siemRaw["syslog_addr"]; ok {
			siemRaw["syslog_udp_addr"] = v
			siemRaw["syslog_tcp_addr"] = v
			delete(siemRaw, "syslog_addr")
			applied = append(applied, "siem.syslog_addr -> siem.syslog_udp_addr+syslog_tcp_addr")
		}
	}
	if sv, ok := raw["server"].(map[string]any); ok {
		if _, hasAddr := sv["addr"]; !hasAddr {
			if h, ok := sv["http_addr"].(string); ok && h != "" {
				sv["addr"] = h
				applied = append(applied, "server.http_addr -> server.addr")
			}
		}
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, out, 0600); err != nil {
		return nil, err
	}
	return applied, nil
}

// --- internals ---

func migrateTopLevelKeys(raw map[string]any) {
	// Old siem keys are handled with warning + best-effort merge in Load.
}

func migratedSIEM(raw map[string]any) (map[string]string, bool) {
	siemRaw, ok := raw["siem"].(map[string]any)
	if !ok {
		return nil, false
	}
	out := map[string]string{}
	if v, ok := siemRaw["log_dir"].(string); ok && v != "" {
		out["log_dir"] = v
	}
	if v, ok := siemRaw["syslog_addr"].(string); ok && v != "" {
		out["syslog_addr"] = v
	}
	return out, len(out) > 0
}

func mergeSIEM(cfg *Config, m map[string]string) {
	if v, ok := m["log_dir"]; ok && len(cfg.SIEM.LogDirs) == 0 {
		cfg.SIEM.LogDirs = []string{v}
	}
	if v, ok := m["syslog_addr"]; ok {
		if cfg.SIEM.SyslogUDPAddr == "" {
			cfg.SIEM.SyslogUDPAddr = v
		}
		if cfg.SIEM.SyslogTCPAddr == "" {
			cfg.SIEM.SyslogTCPAddr = v
		}
	}
}

var knownTopKeys = map[string]bool{
	"db_path": true, "data_dir": true, "log_dir": true, "playbook_dir": true,
	"intel_dir": true, "telemetry": true, "siem": true, "server": true, "tse": true,
	"llm": true, "response": true, "update": true,
	"llm_provider": true, "llm_url": true, "llm_api_key": true, "llm_model": true,
	"vt_api_key": true, "abuseipdb_key": true, "otx_api_key": true, "web_search_key": true,
	"slack_webhook_url": true, "discord_webhook_url": true, "telegram_bot_token": true,
	"telegram_chat_id": true, "smtp_host": true, "smtp_port": true, "smtp_user": true,
	"smtp_password": true, "smtp_from": true, "email_to": true,
	"pagerduty_routing_key": true, "webhook_url": true,
}

func unknownKeyWarnings(raw map[string]any, cfg *Config) []string {
	var warns []string
	for k := range raw {
		if !knownTopKeys[k] {
			warns = append(warns, fmt.Sprintf("unknown config key %q (run `trace config migrate`)", k))
		}
	}
	return warns
}

// warnings registry keyed by pointer (Load-time warnings surfaced by Check).
var warnRegistry = map[string][]string{}

func cfgKey(c *Config) string { return fmt.Sprintf("%p", c) }

func rememberWarnings(c *Config, w []string) {
	if len(w) > 0 {
		warnRegistry[cfgKey(c)] = append(warnRegistry[cfgKey(c)], w...)
	}
}

func pendingWarningsFor(c *Config) []string { return warnRegistry[cfgKey(c)] }

// applyEnv binds TRACE_* / *_FILE via struct tags using reflection.
func applyEnv(cfg *Config) {
	applyEnvToValue(reflect.ValueOf(cfg).Elem())
}

func applyEnvToValue(v reflect.Value) {
	t := v.Type()
	for i := range v.NumField() {
		f := v.Field(i)
		sf := t.Field(i)
		if f.Kind() == reflect.Struct {
			applyEnvToValue(f)
			continue
		}
		// *_FILE first: file path env -> file content (secrets).
		if fileEnv := sf.Tag.Get("fileenv"); fileEnv != "" {
			for _, name := range strings.Split(fileEnv, ",") {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				if p := os.Getenv(name); p != "" {
					if data, err := os.ReadFile(p); err == nil {
						if f.Kind() == reflect.String && f.CanSet() {
							f.SetString(strings.TrimSpace(string(data)))
						}
					} else {
						log.Printf("[config] warn: cannot read secret file %s=%s: %v", name, p, err)
					}
					break
				}
			}
		}
		envTag := sf.Tag.Get("env")
		if envTag == "" {
			continue
		}
		var val string
		for _, name := range strings.Split(envTag, ",") {
			name = strings.TrimSpace(name)
			if v := os.Getenv(name); v != "" {
				val = v
				break
			}
		}
		if val == "" || !f.CanSet() {
			continue
		}
		switch f.Kind() {
		case reflect.String:
			f.SetString(val)
		case reflect.Bool:
			if b, err := strconv.ParseBool(val); err == nil {
				f.SetBool(b)
			}
		case reflect.Int, reflect.Int64, reflect.Int32:
			if n, err := strconv.Atoi(val); err == nil {
				f.SetInt(int64(n))
			}
		case reflect.Float64:
			if n, err := strconv.ParseFloat(val, 64); err == nil {
				f.SetFloat(n)
			}
		case reflect.Slice:
			if f.Type().Elem().Kind() == reflect.String {
				f.Set(reflect.ValueOf(strings.Split(val, ",")))
			}
		}
	}
}

func normalize(cfg *Config) {
	// Deprecated alias: http_addr -> addr (single ServerAddr).
	if cfg.Server.Addr == "" && cfg.Server.HTTPAddr != "" {
		cfg.Server.Addr = cfg.Server.HTTPAddr
	}
	// Canonical default.
	if cfg.Server.Addr == "" {
		cfg.Server.Addr = DefaultServerAddr
	}
	if cfg.LLMProvider == "" {
		cfg.LLMProvider = "openai"
	}
}
