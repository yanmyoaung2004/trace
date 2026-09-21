package otx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCheckIndicator_Table covers the failure matrix callers actually hit:
// 429 rate limit, 500, truncated JSON, and transport timeout.
func TestCheckIndicator_Table(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
		timeout time.Duration
	}{
		{
			name: "rate-limited",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantErr: "rate limited",
		},
		{
			name: "server-error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: "HTTP 500",
		},
		{
			name: "truncated-json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"pulse_info":{"count":`))
			},
			wantErr: "decode",
		},
		{
			name: "timeout",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(300 * time.Millisecond)
			},
			wantErr: "request",
			timeout: 50 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			c := New("test-key", nil)
			c.SetTestURL(server.URL)
			c.httpClient = server.Client()
			if tt.timeout > 0 {
				c.timeout = tt.timeout
			}

			_, err := c.CheckIndicator(context.Background(), "8.8.8.8")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestCheckIndicator_Cache verifies the second lookup for the same indicator
// is served from SQLite without hitting the network again.
func TestCheckIndicator_Cache(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"pulse_info":{"count":2}}`))
	}))
	defer server.Close()

	db := openTestCache(t)
	c := New("test-key", db)
	c.SetTestURL(server.URL)
	c.httpClient = server.Client()

	ctx := context.Background()
	first, err := c.CheckIndicator(ctx, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if first.PulseInfo.Count != 2 {
		t.Fatalf("count = %d, want 2", first.PulseInfo.Count)
	}
	if _, err := c.CheckIndicator(ctx, "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Errorf("server hits = %d, want 1 (second lookup must be cached)", hits)
	}
}
