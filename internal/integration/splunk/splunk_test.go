package splunk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

func TestAgentName(t *testing.T) {
	a := New()
	if a.Name() != "splunk" {
		t.Errorf("name = %q", a.Name())
	}
}

func TestExecute_UnknownAction(t *testing.T) {
	a := New()
	_, err := a.Execute(context.Background(), agent.Input{"action": "unknown"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSearch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		// Splunk returns newline-delimited JSON
		w.Write([]byte(`{"_raw":"error: timeout","host":"server1","source":"/var/log/syslog"}` + "\n"))
	}))
	defer server.Close()

	a := NewWithConfig(AgentConfig{BaseURL: server.URL, Username: "admin", Password: "changeme"})
	out, err := a.Execute(context.Background(), agent.Input{
		"action": "search",
		"query":  "error*",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["count"] != 1 {
		t.Errorf("count = %v, want 1", out["count"])
	}
}

func TestSearch_MissingURL(t *testing.T) {
	a := New()
	out, _ := a.Execute(context.Background(), agent.Input{
		"action": "search",
		"query":  "error*",
	})
	if out["error"] == nil {
		t.Error("expected error for missing config base_url")
	}
}

func TestSavedSearch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"results": []any{map[string]any{"host": "server1"}},
		})
	}))
	defer server.Close()

	a := NewWithConfig(AgentConfig{BaseURL: server.URL, Username: "admin", Password: "changeme"})
	out, err := a.Execute(context.Background(), agent.Input{
		"action":            "saved_search",
		"saved_search_name": "daily_errors",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["count"] != 1 {
		t.Errorf("count = %v, want 1", out["count"])
	}
}

func TestAlert(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"entry":[{"name":"test_alert"}]}`))
	}))
	defer server.Close()

	a := NewWithConfig(AgentConfig{BaseURL: server.URL, Token: "test-token"})
	out, err := a.Execute(context.Background(), agent.Input{
		"action":     "alert",
		"alert_name": "test_alert",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["alert_name"] != "test_alert" {
		t.Errorf("alert_name = %v", out["alert_name"])
	}
	if out["raw"] == "" {
		t.Error("expected raw body")
	}
}
