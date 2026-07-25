package edr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentName(t *testing.T) {
	c := New(Config{Provider: "crowdstrike"})
	if c.Name() != "edr_crowdstrike" {
		t.Errorf("name = %q", c.Name())
	}
}

func TestUnsupportedProvider(t *testing.T) {
	c := New(Config{Provider: "unknown"})
	_, err := c.GetAgentInfo(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}

func crowdStrikeTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	var reqNum int
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqNum++
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/oauth2/token"):
			// Auth request
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token-abc",
				"expires_in":   3600,
			})
		case strings.Contains(r.URL.Path, "/sensors/queries/devices/v1"):
			// Device query
			json.NewEncoder(w).Encode(map[string]any{
				"resources": []string{"device-1"},
			})
		case strings.Contains(r.URL.Path, "/sensors/entities/devices/v1"):
			// Device details
			json.NewEncoder(w).Encode(map[string]any{
				"resources": []any{
					map[string]any{
						"device_id":     "device-1",
						"hostname":      "test-host",
						"status":        "online",
						"platform_name": "Windows",
						"local_ip":      "10.0.0.1",
						"last_seen":     "2026-01-01T00:00:00Z",
					},
				},
			})
		default:
			t.Logf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestCrowdStrike_GetAgent(t *testing.T) {
	server := crowdStrikeTestServer(t)
	defer server.Close()

	c := New(Config{
		Provider:     "crowdstrike",
		BaseURL:      server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})
	c.client = server.Client()

	info, err := c.GetAgentInfo(context.Background(), "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if info.Hostname != "test-host" {
		t.Errorf("hostname = %q", info.Hostname)
	}
	if info.Status != "online" {
		t.Errorf("status = %q", info.Status)
	}
}

func TestCircuitBreaker_BlocksWhenOpen(t *testing.T) {
	c := New(Config{Provider: "crowdstrike"})
	c.cbState = circuitOpen
	c.cbLastFail = time.Now()

	err := c.circuitCheck()
	if err == nil || !strings.Contains(err.Error(), "circuit breaker open") {
		t.Errorf("expected circuit breaker error, got %v", err)
	}
}

func TestCircuitBreaker_AllowsWhenClosed(t *testing.T) {
	c := New(Config{Provider: "crowdstrike"})
	if err := c.circuitCheck(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestCircuitBreaker_HalfOpen(t *testing.T) {
	c := New(Config{Provider: "crowdstrike"})
	c.cbState = circuitHalfOpen
	c.cbFailCount = 3

	if err := c.circuitCheck(); err != nil {
		t.Error("expected half-open to allow requests")
	}
}

func TestCircuitBreaker_OpenExpires(t *testing.T) {
	c := New(Config{Provider: "crowdstrike"})
	c.cbState = circuitOpen
	c.cbLastFail = time.Now().Add(-5 * time.Minute)

	if err := c.circuitCheck(); err != nil {
		t.Error("expected expired circuit to close")
	}
}

func TestCircuitSuccess(t *testing.T) {
	c := New(Config{Provider: "crowdstrike"})
	c.cbState = circuitOpen
	c.cbFailCount = 10

	c.circuitSuccess()
	if c.cbState != circuitClosed {
		t.Error("expected circuit to close")
	}
	if c.cbFailCount != 0 {
		t.Error("expected fail count to reset")
	}
}
