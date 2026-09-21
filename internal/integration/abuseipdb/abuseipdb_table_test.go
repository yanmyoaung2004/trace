package abuseipdb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCheckIP_Table covers the failure matrix callers actually hit: 429 rate
// limit, 500, truncated JSON, transport timeout, and the cache fast path.
func TestCheckIP_Table(t *testing.T) {
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
				w.Write([]byte(`{"data":{"ipAddress":"1.2.3.4",`))
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

			_, err := c.CheckIP(context.Background(), "1.2.3.4")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestCheckIP_Cache verifies the second lookup for the same IP is served from
// SQLite without hitting the network again.
func TestCheckIP_Cache(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"ipAddress":"9.9.9.9","abuseConfidenceScore":10,"totalReports":1,"countryCode":"US"}}`))
	}))
	defer server.Close()

	db := openTestCache(t)
	c := New("test-key", db)
	c.SetTestURL(server.URL)
	c.httpClient = server.Client()

	ctx := context.Background()
	first, err := c.CheckIP(ctx, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if first.Confidence != 10 {
		t.Fatalf("confidence = %d, want 10", first.Confidence)
	}
	if _, err := c.CheckIP(ctx, "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Errorf("server hits = %d, want 1 (second lookup must be cached)", hits)
	}
}
