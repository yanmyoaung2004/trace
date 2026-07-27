package edr_agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type Config struct {
	ServerURL   string `json:"server_url"`
	APIKey      string `json:"api_key"`
	Hostname    string `json:"hostname,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`

	PollInterval    time.Duration `json:"poll_interval"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	BatchInterval   time.Duration `json:"batch_interval"`
	MaxBatchSize    int           `json:"max_batch_size"`
	EventQueueSize  int           `json:"event_queue_size"`

	DataDir    string `json:"data_dir"`
	LogDir     string `json:"log_dir"`
	LogLevel   string `json:"log_level"`

	MonitorProcess  bool `json:"monitor_process"`
	MonitorFile     bool `json:"monitor_file"`
	MonitorNetwork  bool `json:"monitor_network"`
	MonitorRegistry bool `json:"monitor_registry"`
	MonitorFIM      bool `json:"monitor_fim"`
	MonitorETWChannels bool `json:"monitor_etw_channels"`

	WatchPaths    []string `json:"watch_paths"`
	ExcludePaths  []string `json:"exclude_paths"`

	FIMWatchPaths      []string      `json:"fim_watch_paths"`
	FIMExcludePatterns []string      `json:"fim_exclude_patterns"`
	FIMMaxSizeMB       int           `json:"fim_max_size_mb"`
	FIMScanInterval    time.Duration `json:"fim_scan_interval"`

	VulnScanEnabled bool    `json:"vuln_scan_enabled"`
	VulnMinCVSS     float64 `json:"vuln_min_cvss"`
	VulnScanHours   int     `json:"vuln_scan_hours"`

	ResourceLimitCPU    float64 `json:"resource_limit_cpu"`
	ResourceLimitMemory int64   `json:"resource_limit_memory_mb"`
	MaxEventsPerSec     int     `json:"max_events_per_sec"`

	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
	CAFile      string `json:"ca_file"`

	LogCollectPaths []string `json:"log_collect_paths"`
}

func DefaultConfig() *Config {
	hostname, _ := os.Hostname()
	return &Config{
		ServerURL:         "https://127.0.0.1:8080",
		Hostname:          hostname,
		PollInterval:      5 * time.Second,
		HeartbeatInterval: 30 * time.Second,
		BatchInterval:     2 * time.Second,
		MaxBatchSize:      100,
		EventQueueSize:    10000,
		DataDir:           filepath.Join(agentHomeDir(), "data"),
		LogDir:            filepath.Join(agentHomeDir(), "logs"),
		LogLevel:          "info",
		MonitorProcess:    true,
		MonitorFile:       true,
		MonitorNetwork:    true,
		MonitorRegistry:   runtime.GOOS == "windows",
		MonitorFIM:        true,
		MonitorETWChannels: runtime.GOOS == "windows",
		WatchPaths:        defaultWatchPaths(),
		FIMWatchPaths:     defaultFIMPaths(),
		FIMMaxSizeMB:      50,
		FIMScanInterval:   60 * time.Second,
		VulnScanEnabled:   true,
		VulnMinCVSS:       4.0,
		VulnScanHours:     6,
		ResourceLimitCPU:  0.5,
		ResourceLimitMemory: 256,
		MaxEventsPerSec:   500,
		LogCollectPaths:   defaultLogPaths(),
	}
}

func agentHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".trace-agent")
	}
	dir := filepath.Join(home, ".trace-agent")
	os.MkdirAll(dir, 0700)
	return dir
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// MergeRemote applies server-side defaults from a remote config.
// Local file values take precedence (already loaded in cfg).
func (c *Config) MergeRemote(remote map[string]any) {
	if remote == nil {
		return
	}
	setBool := func(field string, target *bool) {
		if v, ok := remote[field].(bool); ok {
			*target = v
		}
	}
	setFloat := func(field string, target *float64) {
		if v, ok := remote[field].(float64); ok {
			*target = v
		}
	}
	setInt := func(field string, target *int) {
		if v, ok := remote[field].(float64); ok {
			*target = int(v)
		}
	}
	setInt64 := func(field string, target *int64) {
		if v, ok := remote[field].(float64); ok {
			*target = int64(v)
		}
	}
	setStr := func(field string, target *string) {
		if v, ok := remote[field].(string); ok {
			*target = v
		}
	}
	setStrSlice := func(field string, target *[]string) {
		if v, ok := remote[field].([]any); ok {
			out := make([]string, len(v))
			for i, s := range v {
				if str, ok := s.(string); ok {
					out[i] = str
				}
			}
			*target = out
		}
	}

	setBool("monitor_process", &c.MonitorProcess)
	setBool("monitor_file", &c.MonitorFile)
	setBool("monitor_network", &c.MonitorNetwork)
	setBool("monitor_registry", &c.MonitorRegistry)
	setBool("monitor_fim", &c.MonitorFIM)
	setBool("vuln_scan_enabled", &c.VulnScanEnabled)
	setFloat("vuln_min_cvss", &c.VulnMinCVSS)
	setInt("vuln_scan_hours", &c.VulnScanHours)
	setFloat("resource_limit_cpu", &c.ResourceLimitCPU)
	setInt64("resource_limit_memory_mb", &c.ResourceLimitMemory)
	setInt("max_events_per_sec", &c.MaxEventsPerSec)
	setStr("log_level", &c.LogLevel)
	setStrSlice("watch_paths", &c.WatchPaths)
	setStrSlice("exclude_paths", &c.ExcludePaths)
	setStrSlice("fim_watch_paths", &c.FIMWatchPaths)
	setStrSlice("fim_exclude_patterns", &c.FIMExcludePatterns)
}

func defaultWatchPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{"C:\\temp", "C:\\Users\\Public", "C:\\Windows\\Temp"}
	}
	return []string{"/tmp", "/var/tmp", "/etc"}
}

func defaultFIMPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			"C:\\Windows\\System32\\drivers\\etc\\hosts",
			"C:\\Windows\\System32\\drivers\\etc\\services",
			"C:\\Windows\\System32\\config",
			"C:\\Program Files",
		}
	}
	return []string{
		"/etc/passwd", "/etc/shadow",
		"/etc/ssh/sshd_config",
		"/bin", "/sbin", "/usr/bin", "/usr/sbin",
	}
}

func defaultLogPaths() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	return []string{
		"/var/log/auth.log",
		"/var/log/syslog",
		"/var/log/messages",
	}
}
