package edge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/investigation"
)

func TestIsAlphaNum(t *testing.T) {
	tests := []struct {
		b    byte
		want bool
	}{
		{'a', true}, {'z', true}, {'A', true}, {'Z', true},
		{'0', true}, {'9', true},
		{'-', false}, {'.', false}, {' ', false},
	}
	for _, tt := range tests {
		got := isAlphaNum(tt.b)
		if got != tt.want {
			t.Errorf("isAlphaNum(%q) = %v, want %v", tt.b, got, tt.want)
		}
	}
}

func TestStringsTrim(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"  hello  ", "hello"},
		{"abc123", "abc123"},
		{"./file.txt", "file.txt"},
	}
	for _, tt := range tests {
		got := stringsTrim(tt.input)
		if got != tt.want {
			t.Errorf("stringsTrim(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractIndicators(t *testing.T) {
	tests := []struct {
		intent string
		want   int
	}{
		{"check file d41d8cd98f00b204e9800998ecf8427e", 1},
		{"no indicators here", 0},
		{"hash1: a000000000000000000000000000000000000000 hash2: b000000000000000000000000000000000000000", 2},
		{"", 0},
	}
	for _, tt := range tests {
		got := extractIndicators(tt.intent)
		if len(got) != tt.want {
			t.Errorf("extractIndicators(%q) = %d indicators, want %d. got %v", tt.intent, len(got), tt.want, got)
		}
	}
}

func TestGenerateSummary(t *testing.T) {
	inv := investigation.Investigation{
		ID:     "00000000-0000-0000-0000-000000000001",
		Intent: "check file hash",
		Status: "open",
	}
	s := generateSummary(inv)
	if s == "" {
		t.Fatal("expected non-empty summary")
	}
}

func TestRegister(t *testing.T) {
	var received struct {
		Hostname string `json:"hostname"`
		Version  string `json:"version"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"node-1"}`))
	}))
	defer server.Close()

	c := NewSyncClient(server.URL, nil)
	c.httpClient = server.Client()

	if err := c.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = received
}

func TestHeartbeat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	c := NewSyncClient(server.URL, nil)
	c.httpClient = server.Client()
	c.nodeID = "node-1"

	if err := c.doHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPostJSON_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"server error"}`))
	}))
	defer server.Close()

	c := NewSyncClient(server.URL, nil)
	c.httpClient = server.Client()

	err := c.postJSON(context.Background(), "/test", map[string]string{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPostJSON_BadRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	c := NewSyncClient(server.URL, nil)
	c.httpClient = server.Client()

	err := c.postJSON(context.Background(), "/test", map[string]string{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}
