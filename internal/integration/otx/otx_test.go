package otx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClassifyIndicator(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "domain"},
		{"http://evil.com/path", "url"},
		{"d41d8cd98f00b204e9800998ecf8427e", "file"},      // 32 hex = MD5 hash → file
		{"a000000000000000000000000000000000000000", "file"}, // 40 hex = SHA1 hash → file
	}
	for _, tt := range tests {
		got := classifyIndicator(tt.input)
		if got != tt.want {
			t.Errorf("classifyIndicator(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCheckIndicator_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pulse_info":{"count":3}}`))
	}))
	defer server.Close()

	c := New("test-key", nil)
	c.SetTestURL(server.URL)

	result, err := c.CheckIndicator(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if result.PulseInfo.Count != 3 {
		t.Errorf("count = %d, want 3", result.PulseInfo.Count)
	}
}

func TestCheckIndicator_NoAPIKey(t *testing.T) {
	c := New("", nil)
	result, err := c.CheckIndicator(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil result with empty API key")
	}
}

func TestCheckIndicator_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := New("key", nil)
	c.SetTestURL(server.URL)

	_, err := c.CheckIndicator(context.Background(), "8.8.8.8")
	if err == nil {
		t.Error("expected error for server error")
	}
}

func TestCheckIndicator_Domain(t *testing.T) {
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pulse_info":{"count":0}}`))
	}))
	defer server.Close()

	c := New("key", nil)
	c.SetTestURL(server.URL)

	c.CheckIndicator(context.Background(), "evil.com")
	if capturedPath != "/api/v1/indicators/domain/evil.com/general" {
		t.Errorf("path = %q, want /api/v1/indicators/domain/evil.com/general", capturedPath)
	}
}

func TestCheckIndicator_File(t *testing.T) {
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pulse_info":{"count":0}}`))
	}))
	defer server.Close()

	hash := "d41d8cd98f00b204e9800998ecf8427e"
	c := New("key", nil)
	c.SetTestURL(server.URL)

	c.CheckIndicator(context.Background(), hash)
	if capturedPath != "/api/v1/indicators/file/"+hash+"/general" {
		t.Errorf("path = %q", capturedPath)
	}
}
