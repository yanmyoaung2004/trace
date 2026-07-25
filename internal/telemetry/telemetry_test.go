package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tr := New(true, "v1.0", "http://example.com")
	if tr == nil {
		t.Fatal("expected non-nil")
	}
	if !tr.enabled {
		t.Error("expected enabled")
	}
}

func TestDisabled(t *testing.T) {
	tr := New(false, "v1.0", "http://example.com")
	tr.Start() // should not panic or send
}

func TestEmptyURL(t *testing.T) {
	tr := New(true, "v1.0", "")
	tr.Start() // should not panic or send
}

func TestSendReport(t *testing.T) {
	var received Report
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pc := func() int { return 5 }
	ic := func() int { return 42 }

	tr := New(true, "v2.0", server.URL)
	tr.WithCounts(pc, ic)

	// Send manually (Start would send on a ticker)
	tr.send()

	if received.Version != "v2.0" {
		t.Errorf("version = %q, want v2.0", received.Version)
	}
	if received.InvestigationCount != 42 {
		t.Errorf("investigation_count = %d, want 42", received.InvestigationCount)
	}
	if received.PluginCount != 5 {
		t.Errorf("plugin_count = %d, want 5", received.PluginCount)
	}
	if received.OS == "" {
		t.Error("expected OS to be set")
	}
	if received.Arch == "" {
		t.Error("expected Arch to be set")
	}
}

func TestSendReport_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	tr := New(true, "v1.0", server.URL)
	tr.send() // should not panic
}

func TestWithCounts(t *testing.T) {
	tr := New(true, "v1.0", "http://example.com")
	tr.WithCounts(func() int { return 1 }, func() int { return 2 })

	if tr.pluginCount == nil || tr.invCount == nil {
		t.Error("expected count functions to be set")
	}
	if tr.pluginCount() != 1 {
		t.Errorf("plugin count = %d", tr.pluginCount())
	}
	if tr.invCount() != 2 {
		t.Errorf("inv count = %d", tr.invCount())
	}
}

func TestStartSendsImmediately(t *testing.T) {
	sent := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tr := New(true, "v1.0", server.URL)
	tr.Start()

	select {
	case <-sent:
		// OK — Start sends immediately
	case <-time.After(time.Second):
		t.Fatal("Start did not send immediately")
	}
}
