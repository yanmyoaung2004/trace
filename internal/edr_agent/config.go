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

	WatchPaths    []string `json:"watch_paths"`
	ExcludePaths  []string `json:"exclude_paths"`

	ResourceLimitCPU    float64 `json:"resource_limit_cpu"`
	ResourceLimitMemory int64   `json:"resource_limit_memory_mb"`
	MaxEventsPerSec     int     `json:"max_events_per_sec"`

	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
	CAFile      string `json:"ca_file"`
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
		WatchPaths:        defaultWatchPaths(),
		ResourceLimitCPU:  0.5,
		ResourceLimitMemory: 256,
		MaxEventsPerSec:   500,
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

func defaultWatchPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{"C:\\temp", "C:\\Users\\Public", "C:\\Windows\\Temp"}
	}
	return []string{"/tmp", "/var/tmp", "/etc"}
}
