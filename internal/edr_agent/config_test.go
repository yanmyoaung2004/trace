package edr_agent

import (
	"testing"
)

func TestMergeRemote_Nil(t *testing.T) {
	c := DefaultConfig()
	prev := c.MonitorProcess
	c.MergeRemote(nil)
	if c.MonitorProcess != prev {
		t.Error("nil merge should not change config")
	}
}

func TestMergeRemote_Bool(t *testing.T) {
	c := DefaultConfig()
	c.MonitorProcess = false

	c.MergeRemote(map[string]any{"monitor_process": true})
	if !c.MonitorProcess {
		t.Error("expected monitor_process=true after merge")
	}
}

func TestMergeRemote_Float(t *testing.T) {
	c := DefaultConfig()
	c.VulnMinCVSS = 0

	c.MergeRemote(map[string]any{"vuln_min_cvss": 7.5})
	if c.VulnMinCVSS != 7.5 {
		t.Errorf("expected vuln_min_cvss=7.5, got %.1f", c.VulnMinCVSS)
	}
}

func TestMergeRemote_IntFromFloat(t *testing.T) {
	c := DefaultConfig()
	c.MaxEventsPerSec = 0

	c.MergeRemote(map[string]any{"max_events_per_sec": float64(1000)})
	if c.MaxEventsPerSec != 1000 {
		t.Errorf("expected max_events_per_sec=1000, got %d", c.MaxEventsPerSec)
	}
}

func TestMergeRemote_String(t *testing.T) {
	c := DefaultConfig()
	c.LogLevel = "debug"

	c.MergeRemote(map[string]any{"log_level": "error"})
	if c.LogLevel != "error" {
		t.Errorf("expected log_level=error, got %s", c.LogLevel)
	}
}

func TestMergeRemote_StringSlice(t *testing.T) {
	c := DefaultConfig()
	c.WatchPaths = nil

	c.MergeRemote(map[string]any{"watch_paths": []any{"/etc", "/tmp"}})
	if len(c.WatchPaths) != 2 || c.WatchPaths[0] != "/etc" {
		t.Errorf("expected watch_paths=[/etc /tmp], got %v", c.WatchPaths)
	}
}

func TestMergeRemote_IgnoresUnknownKeys(t *testing.T) {
	c := DefaultConfig()
	prev := c.LogLevel

	c.MergeRemote(map[string]any{"nonexistent_key": "value"})
	if c.LogLevel != prev {
		t.Error("unknown keys should be ignored")
	}
}

func TestMergeRemote_PartialUpdate(t *testing.T) {
	c := DefaultConfig()
	c.MonitorProcess = false
	c.MonitorFile = false

	c.MergeRemote(map[string]any{"monitor_process": true})
	if !c.MonitorProcess {
		t.Error("expected monitor_process=true")
	}
	if c.MonitorFile {
		t.Error("monitor_file should remain unchanged")
	}
}
