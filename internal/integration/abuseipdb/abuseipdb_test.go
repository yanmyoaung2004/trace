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
		w.Write([]byte(`{"data":{"ip":"8.8.8.8","abuseConfidenceScore":0,"totalReports":0,"countryCode":"US"}}`))
	}))
	defer server.Close()

	client := &Client{
		apiURL:  server.URL + "/",
		apiKey:  "test",
		client:  server.Client(),
	}
	client.apiURL = server.URL + "/"

	result, err := client.CheckIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if result.Data.IP != "8.8.8.8" {
		t.Errorf("ip = %q", result.Data.IP)
	}
}

func TestCheckIP_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &Client{apiURL: server.URL + "/", apiKey: "test", client: server.Client()}
	_, err := client.CheckIP(context.Background(), "8.8.8.8")
	if err == nil {
		t.Error("expected error for server error")
	}
}

func TestCheckIP_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &Client{apiURL: server.URL + "/", apiKey: "test", client: server.Client()}
	_, err := client.CheckIP(context.Background(), "0.0.0.0")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestCheckIP_InvalidIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"ip":"invalid"}}`))
	}))
	defer server.Close()

	client := &Client{apiURL: server.URL + "/", apiKey: "test", client: server.Client()}
	result, err := client.CheckIP(context.Background(), "bad")
	if err != nil {
		t.Fatal(err)
	}
	if result.Data.IP != "invalid" {
		t.Errorf("ip = %q", result.Data.IP)
	}
}
