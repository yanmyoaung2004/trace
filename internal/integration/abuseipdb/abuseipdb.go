package abuseipdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type Client struct {
	apiKey     string
	httpClient *http.Client
	cacheDB    *sql.DB
	mu         sync.Mutex
}

func New(apiKey string, cacheDB *sql.DB) *Client {
	return &Client{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cacheDB:    cacheDB,
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

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("abuseipdb rate limited")
	}
	if resp.StatusCode == 404 {
		return &AbuseData{IP: ip, Confidence: 0, TotalReports: 0}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb HTTP %d", resp.StatusCode)
	}

	var result AbuseResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("abuseipdb decode: %w", err)
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
