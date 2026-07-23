package notifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSlackSendsMessage(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	a := New()
	result, err := a.sendSlack(context.Background(), map[string]any{
		"webhook_url": server.URL,
		"title":       "Test Alert",
		"message":     "This is a test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "sent" {
		t.Errorf("expected sent, got %v", result["status"])
	}
	if received["text"] != "*Test Alert*\nThis is a test" {
		t.Errorf("unexpected text: %v", received["text"])
	}
}

func TestSlackRequiresWebhook(t *testing.T) {
	a := New()
	result, err := a.sendSlack(context.Background(), map[string]any{
		"message": "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error, got %v", result["status"])
	}
}

func TestDiscordSendsEmbed(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	a := New()
	result, err := a.sendDiscord(context.Background(), map[string]any{
		"webhook_url": server.URL,
		"title":       "Test",
		"message":     "Description",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "sent" {
		t.Errorf("expected sent, got %v", result["status"])
	}
	embeds, ok := received["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatal("expected embeds")
	}
	embed := embeds[0].(map[string]any)
	if embed["title"] != "Test" {
		t.Errorf("expected title=Test, got %v", embed["title"])
	}
}

func TestTelegramSendsMessage(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	a := &Agent{
		httpClient:      http.DefaultClient,
		TelegramAPIBase: server.URL,
	}
	result, err := a.sendTelegram(context.Background(), map[string]any{
		"bot_token": "test:token",
		"chat_id":   "12345",
		"message":   "Hello from Trace",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "sent" {
		t.Errorf("expected sent, got %v", result["status"])
	}
	if received["chat_id"] != "12345" {
		t.Errorf("expected chat_id=12345, got %v", received["chat_id"])
	}
	if received["text"] != "Hello from Trace" {
		t.Errorf("unexpected text: %v", received["text"])
	}
}

func TestTelegramMissingFields(t *testing.T) {
	a := New()
	result, err := a.sendTelegram(context.Background(), map[string]any{
		"message": "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error, got %v", result["status"])
	}
}

func TestEmailSendsSMTP(t *testing.T) {
	a := New()
	// Without a real SMTP server, this should fail gracefully
	result, err := a.sendEmail(context.Background(), map[string]any{
		"to":      "test@example.com",
		"subject": "Test",
		"body":    "<h1>Test</h1>",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error (no SMTP server), got %v", result["status"])
	}
}

func TestPagerDutySendsAlert(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	a := &Agent{
		httpClient:       http.DefaultClient,
		PagerDutyAPIBase: server.URL,
	}
	result, err := a.sendPagerDuty(context.Background(), map[string]any{
		"routing_key": "test-key",
		"summary":     "Test alert from Trace",
		"severity":    "critical",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "sent" {
		t.Errorf("expected sent, got %v", result["status"])
	}
	if received["routing_key"] != "test-key" {
		t.Errorf("expected routing_key, got %v", received["routing_key"])
	}
	payload, ok := received["payload"].(map[string]any)
	if !ok {
		t.Fatal("expected payload")
	}
	if payload["summary"] != "Test alert from Trace" {
		t.Errorf("expected summary, got %v", payload["summary"])
	}
}

func TestWebhookSendsBody(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	a := New()
	result, err := a.sendWebhook(context.Background(), map[string]any{
		"url":    server.URL,
		"method": "POST",
		"body":   `{"text":"test"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "sent" {
		t.Errorf("expected sent, got %v", result["status"])
	}
	if receivedBody != `{"text":"test"}` {
		t.Errorf("expected `{\"text\":\"test\"}`, got %s", receivedBody)
	}
}

func TestHTTPRetriesOn5xx(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	a := New()
	result, _ := a.postWebhook(context.Background(), server.URL, map[string]string{"text": "test"})
	if result["status"] != "error" {
		t.Errorf("expected error after retries, got %v", result["status"])
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 retries, got %d", attempts)
	}
}

func TestHTTPNoRetryOn4xx(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	a := New()
	result, _ := a.postWebhook(context.Background(), server.URL, map[string]string{"text": "test"})
	if result["status"] != "error" {
		t.Errorf("expected error, got %v", result["status"])
	}
	if attempts > 1 {
		t.Errorf("expected no retry on 4xx, got %d attempts", attempts)
	}
}

func TestExecuteDispatchesToCorrectChannel(t *testing.T) {
	a := New()

	tests := []struct {
		action string
		hasKey bool
	}{
		{"slack", true},
		{"discord", true},
		{"telegram", true},
		{"email", true},
		{"pagerduty", true},
		{"webhook", true},
		{"unknown", false},
	}

	for _, tc := range tests {
		_, err := a.Execute(context.Background(), map[string]any{"action": tc.action})
		if tc.hasKey && err != nil {
			t.Errorf("expected no error for %s, got %v", tc.action, err)
		}
		if !tc.hasKey && err == nil {
			t.Errorf("expected error for %s", tc.action)
		}
	}
}

func TestNewWithConfigSetsDefaults(t *testing.T) {
	cfg := AgentConfig{
		SlackWebhookURL: "https://hooks.slack.com/test",
		SMTPHost:        "smtp.example.com",
		SMTPPort:        587,
		PagerDutyRoutingKey: "pd-key",
	}
	a := NewWithConfig(cfg)
	if a.SlackWebhookURL != "https://hooks.slack.com/test" {
		t.Errorf("expected webhook URL, got %s", a.SlackWebhookURL)
	}
	if a.SMTPHost != "smtp.example.com" {
		t.Errorf("expected SMTP host, got %s", a.SMTPHost)
	}
	if a.PagerDutyRoutingKey != "pd-key" {
		t.Errorf("expected PD key, got %s", a.PagerDutyRoutingKey)
	}
}

func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://example.com", true},
		{"https://hooks.slack.com/services/T00/B00/xxx", true},
		{"ftp://example.com", false},
		{"", false},
		{"not-a-url", false},
	}
	for _, tc := range tests {
		got := isHTTPURL(tc.url)
		if got != tc.want {
			t.Errorf("isHTTPURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestRetryOnNetworkError(t *testing.T) {
	// Server that closes connection immediately
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server doesn't support hijack")
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer server.Close()

	a := New()
	result, _ := a.postWebhook(context.Background(), server.URL, map[string]string{"text": "test"})
	if result["status"] != "error" {
		t.Errorf("expected error, got %v", result["status"])
	}
}
