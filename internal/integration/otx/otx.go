package otx

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
	"github.com/yanmyoaung2004/trace/internal/integration"
)

type Client struct {
	apiKey     string
	httpClient *http.Client
	cacheDB    *sql.DB
	mu         sync.Mutex
	testURL    string // overrides base URL when set (for testing)
	breaker    *integration.CircuitBreaker
	bulkhead   *integration.Bulkhead
	timeout    time.Duration
}

// SetTestURL overrides the API base URL for testing.
func (c *Client) SetTestURL(url string) {
	c.testURL = url
}

func New(apiKey string, cacheDB *sql.DB) *Client {
	return &Client{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cacheDB:    cacheDB,
		breaker:    integration.NewCircuitBreaker(5, 30*time.Second),
		bulkhead:   integration.NewBulkhead(8),
		timeout:    15 * time.Second,
	}
}

type OTXPulse struct {
	Count int `json:"count"`
}

type OTXResponse struct {
	PulseInfo OTXPulse `json:"pulse_info"`
}

func classifyIndicator(indicator string) string {
	i := strings.TrimSpace(indicator)
	if len(i) == 32 || len(i) == 40 || len(i) == 64 {
		for _, c := range i {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return "domain"
			}
		}
		return "file"
	}
	if strings.Contains(i, "/") {
		return "url"
	}
	if strings.Contains(i, ".") && !strings.Contains(i, " ") {
		return "domain"
	}
	return "ip"
}

func (c *Client) CheckIndicator(ctx context.Context, indicator string) (*OTXResponse, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	if c.cacheDB != nil {
		c.mu.Lock()
		var data string
		err := c.cacheDB.QueryRowContext(ctx,
			`SELECT value FROM cache WHERE key = ? AND ttl > CAST(strftime('%s','now') AS INTEGER)`,
			"otx:"+indicator).Scan(&data)
		c.mu.Unlock()
		if err == nil && data != "" {
			var cached OTXResponse
			if json.Unmarshal([]byte(data), &cached) == nil {
				return &cached, nil
			}
		}
	}

	indicatorType := classifyIndicator(indicator)
	apiURL := c.apiURL(indicatorType, indicator)
	if c.breaker != nil && !c.breaker.Allow() {
		return nil, fmt.Errorf("otx circuit open")
	}
	var result OTXResponse
	var callErr error
	if c.bulkhead != nil {
		callErr = c.bulkhead.Run(ctx, func(ctx context.Context) error {
			return c.fetchIndicator(ctx, apiURL, &result)
		})
	} else {
		callErr = c.fetchIndicator(ctx, apiURL, &result)
	}
	if c.breaker != nil {
		c.breaker.Record(callErr == nil)
	}
	if callErr != nil {
		if strings.Contains(callErr.Error(), "not found") {
			return &OTXResponse{PulseInfo: OTXPulse{Count: 0}}, nil
		}
		return nil, callErr
	}

	if c.cacheDB != nil {
		data, _ := json.Marshal(result)
		c.mu.Lock()
		c.cacheDB.ExecContext(ctx,
			`INSERT OR REPLACE INTO cache (key, value, ttl) VALUES (?, ?, CAST(strftime('%s','now') AS INTEGER) + ?)`,
			"otx:"+indicator, string(data), 3600)
		c.mu.Unlock()
	}

	return &result, nil
}
func (c *Client) fetchIndicator(ctx context.Context, apiURL string, result *OTXResponse) error {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-OTX-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("otx request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return fmt.Errorf("otx not found")
	}
	if resp.StatusCode == 429 {
		return fmt.Errorf("otx rate limited")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("otx HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(result); err != nil {
		return fmt.Errorf("otx decode: %w", err)
	}
	return nil
}

type Agent struct {
	client *Client
}

func NewAgent(apiKey string, cacheDB *sql.DB) *Agent {
	return &Agent{client: New(apiKey, cacheDB)}
}

func (a *Agent) Name() string { return "otx" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "indicator_check", Inputs: []string{"indicator"}, Outputs: []string{"pulse_count", "reputation", "indicator_type"}},
	}
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "indicator_check":
		return a.indicatorCheck(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) indicatorCheck(ctx context.Context, input agent.Input) (agent.Output, error) {
	indicator, _ := input["indicator"].(string)
	if indicator == "" {
		indicator, _ = input["ip"].(string)
	}
	if indicator == "" {
		return agent.Output{"error": "indicator is required"}, nil
	}

	data, err := a.client.CheckIndicator(ctx, indicator)
	if err != nil {
		return agent.Output{"indicator": indicator, "error": err.Error()}, nil
	}
	if data == nil {
		return agent.Output{"indicator": indicator, "message": "OTX not configured (set TRACE_OTX_API_KEY)"}, nil
	}

	reputation := "unknown"
	confidence := 0.0
	if data.PulseInfo.Count >= 5 {
		reputation = "malicious"
		confidence = 0.9
	} else if data.PulseInfo.Count >= 2 {
		reputation = "suspicious"
		confidence = 0.6
	}

	return agent.Output{
		"indicator":      indicator,
		"indicator_type": classifyIndicator(indicator),
		"reputation":     reputation,
		"confidence":     confidence,
		"pulse_count":    data.PulseInfo.Count,
	}, nil
}

// apiURL returns the URL for the given indicator type, using testURL if set.
func (c *Client) apiURL(indicatorType, indicator string) string {
	base := c.testURL
	if base == "" {
		base = "https://otx.alienvault.com"
	}
	switch indicatorType {
	case "file":
		return fmt.Sprintf("%s/api/v1/indicators/file/%s/general", base, indicator)
	case "domain":
		return fmt.Sprintf("%s/api/v1/indicators/domain/%s/general", base, indicator)
	case "url":
		return fmt.Sprintf("%s/api/v1/indicators/url/%s/general", base, indicator)
	default:
		return fmt.Sprintf("%s/api/v1/indicators/ip/%s/general", base, indicator)
	}
}
