package abuseipdb

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
	testURL    string
	breaker    *integration.CircuitBreaker
	bulkhead   *integration.Bulkhead
	timeout    time.Duration
}

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

type AbuseResponse struct {
	Data AbuseData `json:"data"`
}

type AbuseData struct {
	IP             string  `json:"ipAddress"`
	IsPublic       bool    `json:"isPublic"`
	Confidence     int     `json:"abuseConfidenceScore"`
	TotalReports   int     `json:"totalReports"`
	LastReportedAt string  `json:"lastReportedAt"`
	Country        string  `json:"countryCode"`
	UsageType      string  `json:"usageType"`
	ISP            string  `json:"isp"`
	Domain         string  `json:"domain"`
	Hostnames      []string `json:"hostnames"`
}

func (c *Client) CheckIP(ctx context.Context, ip string) (*AbuseData, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	if c.cacheDB != nil {
		c.mu.Lock()
		var data string
		err := c.cacheDB.QueryRowContext(ctx,
			`SELECT value FROM cache WHERE key = ? AND ttl > CAST(strftime('%s','now') AS INTEGER)`,
			"abuse:"+ip).Scan(&data)
		c.mu.Unlock()
		if err == nil && data != "" {
			var cached AbuseData
			if json.Unmarshal([]byte(data), &cached) == nil {
				return &cached, nil
			}
		}
	}

	apiURL := c.apiURL(ip)
	if c.breaker != nil && !c.breaker.Allow() {
		return nil, fmt.Errorf("abuseipdb circuit open")
	}
	var result AbuseResponse
	callErr := error(nil)
	if c.bulkhead != nil {
		callErr = c.bulkhead.Run(ctx, func(ctx context.Context) error {
			return c.fetchIP(ctx, apiURL, &result)
		})
	} else {
		callErr = c.fetchIP(ctx, apiURL, &result)
	}
	if c.breaker != nil {
		c.breaker.Record(callErr == nil || isNotFound(callErr))
	}
	if isNotFound(callErr) {
		return &AbuseData{IP: ip, Confidence: 0, TotalReports: 0}, nil
	}
	if callErr != nil {
		return nil, callErr
	}

	if c.cacheDB != nil {
		data, _ := json.Marshal(result.Data)
		c.mu.Lock()
		c.cacheDB.ExecContext(ctx,
			`INSERT OR REPLACE INTO cache (key, value, ttl) VALUES (?, ?, CAST(strftime('%s','now') AS INTEGER) + ?)`,
			"abuse:"+ip, string(data), 3600)
		c.mu.Unlock()
	}

	return &result.Data, nil
}

type Agent struct {
	client *Client
}

func NewAgent(apiKey string, cacheDB *sql.DB) *Agent {
	return &Agent{client: New(apiKey, cacheDB)}
}

func (c *Client) fetchIP(ctx context.Context, apiURL string, result *AbuseResponse) error {
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
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("abuseipdb request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 429 {
		return fmt.Errorf("abuseipdb rate limited")
	}
	if resp.StatusCode == 404 {
		return fmt.Errorf("abuseipdb not found")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("abuseipdb HTTP %d", resp.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := dec.Decode(result); err != nil {
		return fmt.Errorf("abuseipdb decode: %w", err)
	}
	return nil
}
func isNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}
func (a *Agent) Name() string { return "abuseipdb" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "ip_reputation", Inputs: []string{"ip"}, Outputs: []string{"confidence", "reports", "country", "usage"}},
	}
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "ip_reputation":
		return a.ipReputation(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) ipReputation(ctx context.Context, input agent.Input) (agent.Output, error) {
	ip, _ := input["ip"].(string)
	if ip == "" {
		ip, _ = input["indicator"].(string)
	}
	if ip == "" {
		return agent.Output{"error": "ip is required"}, nil
	}

	data, err := a.client.CheckIP(ctx, ip)
	if err != nil {
		return agent.Output{"error": err.Error()}, nil
	}
	if data == nil {
		return agent.Output{"ip": ip, "message": "AbuseIPDB not configured (set TRACE_ABUSEIPDB_KEY)"}, nil
	}

	reputation := "unknown"
	confidence := float64(data.Confidence) / 100.0
	if data.Confidence >= 50 {
		reputation = "malicious"
	} else if data.Confidence >= 25 {
		reputation = "suspicious"
	}

	return agent.Output{
		"ip":              data.IP,
		"reputation":      reputation,
		"abuse_confidence": confidence,
		"total_reports":    data.TotalReports,
		"last_reported":    data.LastReportedAt,
		"country":          data.Country,
		"usage_type":       data.UsageType,
		"isp":              data.ISP,
		"domain":           data.Domain,
	}, nil
}

func (c *Client) apiURL(ip string) string {
	base := c.testURL
	if base == "" {
		base = "https://api.abuseipdb.com"
	}
	return fmt.Sprintf("%s/api/v2/check?ipAddress=%s&maxAgeInDays=90", base, ip)
}
