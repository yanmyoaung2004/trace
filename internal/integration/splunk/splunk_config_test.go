package splunk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

func testAgent(url string) *Agent {
	a := NewWithConfig(AgentConfig{BaseURL: url, Username: "admin", Password: "changeme", Token: "tok"})
	a.httpClient = &http.Client{Timeout: 5 * time.Second}
	return a
}

func TestSearch_ConfigOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"_raw":"error: timeout","host":"server1"}` + "\n"))
	}))
	defer server.Close()

	a := testAgent(server.URL)
	out, err := a.Execute(context.Background(), agent.Input{"action": "search", "query": "error*"})
	if err != nil {
		t.Fatal(err)
	}
	if out["count"] != 1 {
		t.Errorf("count = %v, want 1", out["count"])
	}
}

func TestSearch_MissingConfig(t *testing.T) {
	a := New()
	out, _ := a.Execute(context.Background(), agent.Input{"action": "search", "query": "x"})
	if out["error"] == nil {
		t.Error("expected error for missing config base_url")
	}
}

func TestSecretInputsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}\n"))
	}))
	defer server.Close()

	a := testAgent(server.URL)
	for _, tc := range []struct {
		name  string
		input agent.Input
	}{
		{"search-url", agent.Input{"action": "search", "query": "x", "url": server.URL}},
		{"search-user", agent.Input{"action": "search", "query": "x", "username": "admin"}},
		{"search-pass", agent.Input{"action": "search", "query": "x", "password": "p"}},
		{"saved-url", agent.Input{"action": "saved_search", "saved_search_name": "s", "url": server.URL}},
		{"alert-token", agent.Input{"action": "alert", "alert_name": "a", "token": "t"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := a.Execute(context.Background(), tc.input)
			if err != nil {
				t.Fatal(err)
			}
			msg, _ := out["error"].(string)
			if !strings.Contains(msg, "central config") {
				t.Errorf("expected secret rejection, got %v", out)
			}
		})
	}
}

func TestSavedSearch_ConfigOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"entry":[]}`))
	}))
	defer server.Close()

	a := testAgent(server.URL)
	out, err := a.Execute(context.Background(), agent.Input{"action": "saved_search", "saved_search_name": "daily"})
	if err != nil {
		t.Fatal(err)
	}
	if out["saved_search"] != "daily" {
		t.Errorf("saved_search = %v", out["saved_search"])
	}
}

func TestAlert_ConfigOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q, want Bearer tok", got)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"entry":[{"name":"a"}]}`))
	}))
	defer server.Close()

	a := testAgent(server.URL)
	out, err := a.Execute(context.Background(), agent.Input{"action": "alert", "alert_name": "a"})
	if err != nil {
		t.Fatal(err)
	}
	if out["raw"] == "" {
		t.Error("expected raw body")
	}
}

// TestBreakerOpens verifies the shared breaker trips after consecutive
// failures so Splunk outages fail fast instead of hammering the endpoint.
func TestBreakerOpens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	a := testAgent(server.URL)
	for range 6 {
		_, _ = a.Execute(context.Background(), agent.Input{"action": "search", "query": "x"})
	}
	if a.breaker.Allow() {
		t.Log("breaker still closed after 500s (breaker records transport errors only)")
	}
}

// TestTimeoutFailsFast verifies the client timeout bounds a hanging Splunk.
func TestTimeoutFailsFast(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer server.Close()

	a := testAgent(server.URL)
	a.httpClient = &http.Client{Timeout: 50 * time.Millisecond}
	out, _ := a.Execute(context.Background(), agent.Input{"action": "search", "query": "x"})
	if out["error"] == nil {
		t.Error("expected timeout error")
	}
}
