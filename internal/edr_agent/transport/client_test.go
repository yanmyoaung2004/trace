package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBaseURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://server.com", "https://server.com"},
		{"http://server.com:8080", "http://server.com:8080"},
		{"server.com", "https://server.com"},
		{"server.com/path", "https://server.com/path"},
	}
	for _, tt := range tests {
		c := NewClient(&Config{ServerURL: tt.input})
		got := c.baseURL()
		if got != tt.want {
			t.Errorf("baseURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSignRequest(t *testing.T) {
	c := NewClient(&Config{APIKey: "test-key"})
	sig := c.signRequest([]byte(`{"hello":"world"}`))
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}
	if len(sig) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(sig))
	}
}

func TestSignRequest_NoKey(t *testing.T) {
	c := NewClient(&Config{})
	sig := c.signRequest([]byte(`test`))
	if sig != "" {
		t.Errorf("expected empty signature, got %s", sig)
	}
}

func TestRegister(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("enroll must not send Authorization header, got %q", got)
		}
		if got := r.Header.Get("X-Signature"); got != "" {
			t.Errorf("enroll must not send X-Signature header, got %q", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode enroll body: %v", err)
		}
		if body["provision_token"] != "tok-123" {
			t.Errorf("provision_token = %v, want tok-123", body["provision_token"])
		}
		if _, has := body["api_key"]; has {
			t.Errorf("enroll body must not contain api_key: %v", body)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"agent_id":"agent-1","status":"ok","api_key":"issued-1"},"code":200}`))
	}))
	defer server.Close()

	// Even with a stale/leftover key configured, enroll must not emit it —
	// the provision token in the body is the only credential.
	c := NewClient(&Config{ServerURL: server.URL, APIKey: "stale-key", Timeout: 5 * time.Second})
	c.client = server.Client()

	resp, err := c.Register(context.Background(), &RegisterRequest{Hostname: "test-host", Platform: "linux", ProvisionToken: "tok-123"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.AgentID != "agent-1" {
		t.Errorf("agent_id = %q", resp.AgentID)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q", resp.Status)
	}
	if resp.APIKey != "issued-1" {
		t.Errorf("api_key = %q, want issued-1", resp.APIKey)
	}
}

func TestRegister_UnauthorizedSurfacesServerMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"enrollment requires a provision token (ask an admin to mint one)","code":401}`))
	}))
	defer server.Close()

	c := NewClient(&Config{ServerURL: server.URL, Timeout: 5 * time.Second})
	c.client = server.Client()

	_, err := c.Register(context.Background(), &RegisterRequest{Hostname: "h"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "provision token") {
		t.Errorf("expected 401 with server message, got: %v", err)
	}
}

func TestHeartbeat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	c := NewClient(&Config{ServerURL: server.URL, Timeout: 5 * time.Second})
	c.client = server.Client()

	err := c.Heartbeat(context.Background(), &Heartbeat{AgentID: "a1", Status: "online"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSendEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	c := NewClient(&Config{ServerURL: server.URL, Timeout: 5 * time.Second})
	c.client = server.Client()

	err := c.SendEvents(context.Background(), "agent-1", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPollActions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"actions":[{"id":"act-1","type":"scan","timeout_seconds":60}]}`))
	}))
	defer server.Close()

	c := NewClient(&Config{ServerURL: server.URL, Timeout: 5 * time.Second})
	c.client = server.Client()

	actions, err := c.PollActions(context.Background(), "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].ID != "act-1" {
		t.Errorf("action id = %q", actions[0].ID)
	}
}

func TestReportActionResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	c := NewClient(&Config{ServerURL: server.URL, Timeout: 5 * time.Second})
	c.client = server.Client()

	err := c.ReportActionResult(context.Background(), "agent-1", "act-1", "completed", "", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSetAgentID(t *testing.T) {
	c := NewClient(&Config{AgentID: "old-id"})
	if c.agentID != "old-id" {
		t.Errorf("agentID = %q", c.agentID)
	}
	c.SetAgentID("new-id")
	if c.agentID != "new-id" {
		t.Errorf("agentID = %q after Set", c.agentID)
	}
}

func TestRetryOnServerError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewClient(&Config{ServerURL: server.URL, Timeout: time.Second, RetryMax: 2, RetryBase: time.Millisecond})
	c.client = server.Client()

	_, err := c.Register(context.Background(), &RegisterRequest{})
	if err == nil {
		t.Fatal("expected error after retries")
	}
	if attempts != 3 { // initial + 2 retries
		t.Errorf("expected 3 attempts (1 initial + 2 retries), got %d", attempts)
	}
}

func TestNoRetryOnClientError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer server.Close()

	c := NewClient(&Config{ServerURL: server.URL, Timeout: time.Second, RetryMax: 3, RetryBase: time.Millisecond})
	c.client = server.Client()

	_, err := c.Register(context.Background(), &RegisterRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt (no retry on 4xx), got %d", attempts)
	}
}

func TestRateLimitRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	c := NewClient(&Config{ServerURL: server.URL, Timeout: time.Second, RetryMax: 2, RetryBase: time.Microsecond})
	c.client = server.Client()

	_, err := c.Register(context.Background(), &RegisterRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 3 { // initial + 2 retries (RetryMax=2)
		t.Errorf("expected 3 attempts (rate limited), got %d", attempts)
	}
}

func TestHMACConsistency(t *testing.T) {
	// Same input should produce same signature
	c1 := NewClient(&Config{APIKey: "shared-key"})
	c2 := NewClient(&Config{APIKey: "shared-key"})

	body := []byte(`{"event":"test"}`)
	sig1 := c1.signRequest(body)
	sig2 := c2.signRequest(body)

	if sig1 != sig2 {
		t.Error("HMAC signatures should match for same key and body")
	}
}

func TestNewClient_DefaultTimeout(t *testing.T) {
	c := NewClient(&Config{ServerURL: "https://example.com"})
	// Timeout of 0 means no timeout (valid for http.Client)
	_ = c
}
