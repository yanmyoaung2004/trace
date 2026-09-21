package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

// Connector is the shared HTTP adapter for all external integrations:
// base URL + timeout + auth headers + verified TLS. No
// InsecureSkipVerify anywhere; tests use httptest TLS servers instead.
type Connector struct {
	client  *http.Client
	baseURL string
	headers map[string]string
	timeout time.Duration
}

// ConnectorConfig carries per-connector wiring. Auth is config-supplied,
// never LLM-supplied.
type ConnectorConfig struct {
	BaseURL string
	Timeout time.Duration
	Headers map[string]string
	Client  *http.Client
}

// NewConnector builds a verified-TLS connector.
func NewConnector(cfg ConnectorConfig) *Connector {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := cfg.Client
	if client == nil {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
		client = &http.Client{Timeout: timeout, Transport: transport}
	}
	return &Connector{client: client, baseURL: cfg.BaseURL, headers: cfg.Headers, timeout: timeout}
}

// DoJSON performs method + path with an optional JSON body, returning the
// raw body. 429/5xx surface as typed errors for breaker/bulkhead handling.
func (c *Connector) DoJSON(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var rdr *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal: %w", err)
		}
		rdr = bytes.NewReader(data)
	} else {
		rdr = bytes.NewReader(nil)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read body: %w", err)
	}
	switch {
	case resp.StatusCode == 429:
		return data, resp.StatusCode, fmt.Errorf("rate limited (429)")
	case resp.StatusCode >= 500:
		return data, resp.StatusCode, fmt.Errorf("upstream %d", resp.StatusCode)
	case resp.StatusCode >= 400:
		return data, resp.StatusCode, fmt.Errorf("request failed: HTTP %d", resp.StatusCode)
	}
	return data, resp.StatusCode, nil
}

// CircuitBreaker is a tiny closed/open breaker per external dependency.
type CircuitBreaker struct {
	failures  int
	threshold int
	until     time.Time
	cooldown  time.Duration
}

// NewCircuitBreaker trips after threshold consecutive failures.
func NewCircuitBreaker(threshold int, cooldown time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &CircuitBreaker{threshold: threshold, cooldown: cooldown}
}

// Allow reports whether a call may proceed.
func (b *CircuitBreaker) Allow() bool { return time.Now().After(b.until) }

// Record records success (true) or failure (false).
func (b *CircuitBreaker) Record(ok bool) {
	if ok {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.until = time.Now().Add(b.cooldown)
		b.failures = 0
	}
}

// Bulkhead bounds concurrent calls per external.
type Bulkhead struct {
	sem chan struct{}
}

// NewBulkhead caps in-flight calls at n.
func NewBulkhead(n int) *Bulkhead {
	if n <= 0 {
		n = 8
	}
	return &Bulkhead{sem: make(chan struct{}, n)}
}

// Run executes fn when a slot is free, else returns an error.
func (b *Bulkhead) Run(ctx context.Context, fn func(ctx context.Context) error) error {
	select {
	case b.sem <- struct{}{}:
		defer func() { <-b.sem }()
		return fn(ctx)
	default:
		return fmt.Errorf("bulkhead full")
	}
}

// FanOut runs fns concurrently, collecting the first error.
func FanOut(ctx context.Context, fns ...func(ctx context.Context) error) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, fn := range fns {
		g.Go(func() error { return fn(ctx) })
	}
	return g.Wait()
}
