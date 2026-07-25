package abuseipdb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentName(t *testing.T) {
	a := NewAgent("key", nil)
	if a.Name() == "" {
		t.Error("expected non-empty name")
	}
}

func TestCheckIP_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":0,"totalReports":0,"countryCode":"US"}}`))
	}))
	defer server.Close()

	c := New("test-key", nil)
	c.SetTestURL(server.URL)
	c.httpClient = server.Client()

	result, err := c.CheckIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if result.IP != "8.8.8.8" {
		t.Errorf("ip = %q", result.IP)
	}
}

func TestCheckIP_NoAPIKey(t *testing.T) {
	c := New("", nil)
	result, err := c.CheckIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected nil result with empty API key")
	}
}

func TestCheckIP_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := New("key", nil)
	c.SetTestURL(server.URL)
	c.httpClient = server.Client()

	_, err := c.CheckIP(context.Background(), "8.8.8.8")
	if err == nil {
		t.Error("expected error for server error")
	}
}

func TestCheckIP_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	c := New("key", nil)
	c.SetTestURL(server.URL)
	c.httpClient = server.Client()

	result, err := c.CheckIP(context.Background(), "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	// 404 may return nil response with no error (API returns empty)
	_ = result
}
