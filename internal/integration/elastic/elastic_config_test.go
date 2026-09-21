package elastic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

func testAgent(url string) *Agent {
	a := NewWithConfig(AgentConfig{BaseURL: url, APIKey: "k"})
	a.httpClient = &http.Client{Timeout: 5 * time.Second}
	return a
}

func TestSearch_ConfigOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "ApiKey k" {
			t.Errorf("Authorization = %q, want ApiKey k", got)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(esResponse([]map[string]any{
			{"_id": "doc1", "_source": map[string]any{"message": "test"}},
		}))
	}))
	defer server.Close()

	a := testAgent(server.URL)
	out, err := a.Execute(context.Background(), agent.Input{"action": "search", "index": "logs-*", "query": `{"match_all":{}}`})
	if err != nil {
		t.Fatal(err)
	}
	if out["count"] != 1 {
		t.Errorf("count = %v, want 1", out["count"])
	}
}

func TestSearch_MissingConfig(t *testing.T) {
	a := New()
	out, _ := a.Execute(context.Background(), agent.Input{"action": "search"})
	if out["error"] != "elastic base_url is required (central config)" {
		t.Errorf("error = %v", out["error"])
	}
}

func TestSecretInputsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer server.Close()

	a := testAgent(server.URL)
	for _, tc := range []struct {
		name  string
		input agent.Input
	}{
		{"search-url", agent.Input{"action": "search", "url": server.URL}},
		{"search-key", agent.Input{"action": "search", "api_key": "evil"}},
		{"alert-url", agent.Input{"action": "alert", "url": server.URL}},
		{"indices-key", agent.Input{"action": "indices", "api_key": "evil"}},
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

func TestServerErrorSurfaced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer server.Close()

	a := testAgent(server.URL)
	out, _ := a.Execute(context.Background(), agent.Input{"action": "search", "query": "{}"})
	if out["error"] == nil {
		t.Error("expected error for 500")
	}
}

func TestTruncatedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"hits":{"hits":[{broken`))
	}))
	defer server.Close()

	a := testAgent(server.URL)
	out, err := a.Execute(context.Background(), agent.Input{"action": "search", "query": "{}"})
	if err != nil {
		t.Fatal(err)
	}
	if out["count"] != 0 {
		t.Errorf("count = %v, want 0 for truncated JSON", out["count"])
	}
}

func TestTimeoutFailsFast(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer server.Close()

	a := testAgent(server.URL)
	a.httpClient = &http.Client{Timeout: 50 * time.Millisecond}
	out, _ := a.Execute(context.Background(), agent.Input{"action": "search"})
	if out["error"] == nil {
		t.Error("expected timeout error")
	}
}
