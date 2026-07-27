package server

import (
	"testing"
)

func TestRemoteConfigStore_GetSet(t *testing.T) {
	dir := t.TempDir()
	s := newRemoteConfigStore(dir)

	got := s.Get()
	if got.LogLevel != nil {
		t.Error("expected empty config initially")
	}

	lvl := "error"
	err := s.Set(AgentRemoteConfig{LogLevel: &lvl})
	if err != nil {
		t.Fatal(err)
	}

	got = s.Get()
	if got.LogLevel == nil || *got.LogLevel != "error" {
		t.Errorf("expected log_level=error, got %v", *got.LogLevel)
	}
}

func TestRemoteConfigStore_Persists(t *testing.T) {
	dir := t.TempDir()
	lvl := "info"
	s := newRemoteConfigStore(dir)
	s.Set(AgentRemoteConfig{LogLevel: &lvl})

	// Create new store pointing to same dir
	s2 := newRemoteConfigStore(dir)
	got := s2.Get()
	if got.LogLevel == nil || *got.LogLevel != "info" {
		t.Errorf("expected log_level=info after reload, got %v", got.LogLevel)
	}
}

func TestRemoteConfigStore_MultipleFields(t *testing.T) {
	dir := t.TempDir()
	s := newRemoteConfigStore(dir)

	enabled := true
	cpu := 0.75
	err := s.Set(AgentRemoteConfig{
		MonitorProcess:   &enabled,
		ResourceLimitCPU: &cpu,
	})
	if err != nil {
		t.Fatal(err)
	}

	got := s.Get()
	if got.MonitorProcess == nil || !*got.MonitorProcess {
		t.Error("expected monitor_process=true")
	}
	if got.ResourceLimitCPU == nil || *got.ResourceLimitCPU != 0.75 {
		t.Errorf("expected ResourceLimitCPU=0.75, got %v", got.ResourceLimitCPU)
	}
}
