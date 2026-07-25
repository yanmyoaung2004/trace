package elastic

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
	if a.Name() != "elastic" {
		t.Errorf("name = %q", a.Name())
	}
}

func TestExecute_UnknownAction(t *testing.T) {
	a := New()
	_, err := a.Execute(context.Background(), agent.Input{"action": "unknown"})
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestSearch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(esResponse([]map[string]any{
			{"_id": "doc1", "_source": map[string]any{"message": "test"}},
		}))
	}))
	defer server.Close()

	a := New()
	out, err := a.Execute(context.Background(), agent.Input{
		"action":  "search",
		"url":     server.URL,
		"api_key": "test",
		"index":   "logs-*",
		"query":   `{"match_all":{}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["count"] != 1 {
		t.Errorf("count = %v, want 1", out["count"])
	}
}

func esResponse(hits []map[string]any) map[string]any {
	return map[string]any{
		"hits": map[string]any{
			"total": map[string]any{"value": len(hits)},
			"hits":  hits,
		},
	}
}

func TestSearch_MissingURL(t *testing.T) {
	a := New()
	out, _ := a.Execute(context.Background(), agent.Input{
		"action": "search",
	})
	if out["error"] != "url is required" {
		t.Errorf("error = %v", out["error"])
	}
}

func TestAlerts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"alert_id":"a1","rule_id":"rule-1"}]`))
	}))
	defer server.Close()

	a := New()
	out, err := a.Execute(context.Background(), agent.Input{
		"action":  "alert",
		"url":     server.URL,
		"api_key": "test",
		"rule_id": "rule-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["rule_id"] != "rule-1" {
		t.Errorf("rule_id = %v", out["rule_id"])
	}
	if out["alerts"] == "" {
		t.Error("expected non-empty alerts")
	}
}

func TestListIndices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]any{
			{"index": "logs-2026.01"},
			{"index": "logs-2026.02"},
		})
	}))
	defer server.Close()

	a := New()
	out, err := a.Execute(context.Background(), agent.Input{
		"action":  "indices",
		"url":     server.URL,
		"api_key": "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range out {
		t.Logf("  %s = %v (type %T)", k, v, v)
	}
	if out["count"] != 2 {
		t.Errorf("count = %v (type %T), want 2", out["count"], out["count"])
	}
}
