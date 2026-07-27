package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// AgentRemoteConfig holds server-managed defaults pushed to EDR agents.
type AgentRemoteConfig struct {
	MonitorProcess    *bool    `json:"monitor_process,omitempty"`
	MonitorFile       *bool    `json:"monitor_file,omitempty"`
	MonitorNetwork    *bool    `json:"monitor_network,omitempty"`
	MonitorRegistry   *bool    `json:"monitor_registry,omitempty"`
	MonitorFIM        *bool    `json:"monitor_fim,omitempty"`
	VulnScanEnabled   *bool    `json:"vuln_scan_enabled,omitempty"`
	VulnMinCVSS       *float64 `json:"vuln_min_cvss,omitempty"`
	VulnScanHours     *int     `json:"vuln_scan_hours,omitempty"`
	ResourceLimitCPU  *float64 `json:"resource_limit_cpu,omitempty"`
	ResourceLimitMem  *int64   `json:"resource_limit_memory_mb,omitempty"`
	MaxEventsPerSec   *int     `json:"max_events_per_sec,omitempty"`
	LogLevel          *string  `json:"log_level,omitempty"`
	PollInterval      *string  `json:"poll_interval,omitempty"`
	HeartbeatInterval *string  `json:"heartbeat_interval,omitempty"`
	BatchInterval     *string  `json:"batch_interval,omitempty"`
	MaxBatchSize      *int     `json:"max_batch_size,omitempty"`
}

type remoteConfigStore struct {
	mu   sync.RWMutex
	path string
	cfg  AgentRemoteConfig
}

func newRemoteConfigStore(dataDir string) *remoteConfigStore {
	dir := filepath.Join(dataDir, "config")
	os.MkdirAll(dir, 0700)
	s := &remoteConfigStore{
		path: filepath.Join(dir, "agent_defaults.json"),
	}
	s.load()
	return s
}

func (s *remoteConfigStore) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	json.Unmarshal(data, &s.cfg)
}

func (s *remoteConfigStore) Get() AgentRemoteConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *remoteConfigStore) Set(cfg AgentRemoteConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(s.path, data, 0644); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}
