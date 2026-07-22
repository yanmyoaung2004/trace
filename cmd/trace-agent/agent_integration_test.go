//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/edr_agent"
)

func TestAgentRegistrationAndHeartbeat(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	dir := t.TempDir()
	var registered atomic.Bool
	var heartbeats atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/edr/register":
			registered.Store(true)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"agent_id":"test-id-123","status":"registered"}`))
		case "/api/v1/edr/heartbeat":
			heartbeats.Add(1)
			w.WriteHeader(http.StatusOK)
		case "/api/v1/edr/events":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"stored":1,"received":1}`))
		default:
			t.Logf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cfg := edr_agent.DefaultConfig()
	cfg.ServerURL = ts.URL
	cfg.APIKey = "test-key"
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.HeartbeatInterval = 100 * time.Millisecond
	cfg.PollInterval = 500 * time.Millisecond
	cfg.MonitorProcess = false
	cfg.MonitorFile = false
	cfg.MonitorNetwork = false

	agent := edr_agent.New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		t.Fatalf("agent start: %v", err)
	}

	time.Sleep(2 * time.Second)

	if !registered.Load() {
		t.Error("agent did not register with server")
	}
	if heartbeats.Load() < 5 {
		t.Errorf("expected at least 5 heartbeats, got %d", heartbeats.Load())
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := agent.Stop(stopCtx); err != nil {
		t.Errorf("agent stop: %v", err)
	}
}

func TestAgentSendsEvents(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	dir := t.TempDir()
	var eventsReceived int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/edr/register":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"agent_id":"test-id-events","status":"registered"}`))
		case "/api/v1/edr/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/edr/events":
			atomic.AddInt64(&eventsReceived, 1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"stored":1,"received":1}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cfg := edr_agent.DefaultConfig()
	cfg.ServerURL = ts.URL
	cfg.APIKey = "test-key"
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.HeartbeatInterval = 500 * time.Millisecond
	cfg.BatchInterval = 100 * time.Millisecond
	cfg.MaxBatchSize = 10
	cfg.MonitorProcess = false
	cfg.MonitorFile = false
	cfg.MonitorNetwork = false

	agent := edr_agent.New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		t.Fatalf("agent start: %v", err)
	}

	time.Sleep(3 * time.Second)

	if eventsReceived.Load() == 0 {
		t.Error("agent did not send any events")
	}

	t.Logf("events received: %d", eventsReceived.Load())

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	agent.Stop(stopCtx)
}

func TestAgentRecoversFromServerDown(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	dir := t.TempDir()
	var reqCount int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reqCount, 1)
		count := atomic.LoadInt64(&reqCount)
		if count < 5 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/api/v1/edr/register":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"agent_id":"recovery-test","status":"registered"}`))
		case "/api/v1/edr/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/edr/events":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"stored":1,"received":1}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cfg := edr_agent.DefaultConfig()
	cfg.ServerURL = ts.URL
	cfg.APIKey = "test-key"
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.HeartbeatInterval = 200 * time.Millisecond
	cfg.BatchInterval = 200 * time.Millisecond
	cfg.MonitorProcess = false
	cfg.MonitorFile = false
	cfg.MonitorNetwork = false

	agent := edr_agent.New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		t.Fatalf("agent start: %v", err)
	}

	time.Sleep(4 * time.Second)
	// Agent should have recovered after server started accepting
	t.Logf("total requests: %d", atomic.LoadInt64(&reqCount))

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	agent.Stop(stopCtx)
}

func TestAgentDiskQueueFull(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	dir := t.TempDir()
	serverBlocked := true

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serverBlocked {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/api/v1/edr/register":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"agent_id":"queue-test","status":"registered"}`))
		case "/api/v1/edr/events":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"stored":1,"received":1}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	cfg := edr_agent.DefaultConfig()
	cfg.ServerURL = ts.URL
	cfg.APIKey = "test-key"
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.HeartbeatInterval = time.Hour
	cfg.BatchInterval = 100 * time.Millisecond
	cfg.MaxBatchSize = 5
	cfg.MonitorProcess = false
	cfg.MonitorFile = false
	cfg.MonitorNetwork = false

	agent := edr_agent.New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		t.Fatalf("agent start: %v", err)
	}

	time.Sleep(3 * time.Second)

	serverBlocked = false
	time.Sleep(5 * time.Second)

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	agent.Stop(stopCtx)
}

func TestAgentConfigPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	dir := t.TempDir()
	cfg := edr_agent.DefaultConfig()
	cfg.APIKey = "persist-key"
	cfg.ServerURL = "https://persist-test:8080"
	cfg.DataDir = filepath.Join(dir, "data")

	// Save and reload
	cfgPath := filepath.Join(dir, "config.json")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	loaded, err := edr_agent.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.APIKey != "persist-key" {
		t.Errorf("API key persistence: got %s", loaded.APIKey)
	}
	if loaded.ServerURL != "https://persist-test:8080" {
		t.Errorf("ServerURL persistence: got %s", loaded.ServerURL)
	}
}

var _ = json.Marshal
var _ = os.DevNull
var _ = fmt.Sprintf
