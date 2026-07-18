package detection

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
)

type VTClient struct {
	apiKey     string
	httpClient *http.Client
	cacheDB    *sql.DB
	rateLimit  *sync.Mutex
	lastCall   time.Time
	minInterval time.Duration
}

func NewVTClient(apiKey string, cacheDB *sql.DB) *VTClient {
	return &VTClient{
		apiKey:      apiKey,
		httpClient:  &http.Client{Timeout: 15 * time.Second},
		cacheDB:     cacheDB,
		rateLimit:   &sync.Mutex{},
		minInterval: 15 * time.Second,
	}
}

type VTResult struct {
	Hash          string            `json:"hash"`
	Indicator     string            `json:"indicator"`
	Type          string            `json:"type"`
	Malicious     int               `json:"malicious"`
	Suspicious    int               `json:"suspicious"`
	Undetected    int               `json:"undetected"`
	Total         int               `json:"total"`
	Reputation    string            `json:"reputation"`
	LastAnalysis  string            `json:"last_analysis"`
	Vendors       []VTVerdict       `json:"vendors"`
	Error         string            `json:"error,omitempty"`
}

type VTVerdict struct {
	Vendor   string `json:"vendor"`
	Result   string `json:"result"`
	Category string `json:"category"`
}

func (c *VTClient) LookupHash(ctx context.Context, hash string) (*VTResult, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if !isValidHash(hash) {
		return nil, fmt.Errorf("invalid hash format: %s", hash)
	}

	cached, err := c.checkCache(ctx, hash)
	if err == nil && cached != nil {
		return cached, nil
	}

	if c.apiKey == "" {
		return &VTResult{
			Hash:       hash,
			Indicator:  hash,
			Type:       "hash",
			Reputation: "unknown",
			Error:      "VT API key not configured (set INNO_VT_API_KEY)",
		}, nil
	}

	c.rateLimit.Lock()
	elapsed := time.Since(c.lastCall)
	if elapsed < c.minInterval {
		time.Sleep(c.minInterval - elapsed)
	}
	c.lastCall = time.Now()
	c.rateLimit.Unlock()

	return c.fetchFromVT(ctx, hash)
}

func (c *VTClient) LookupURL(ctx context.Context, url string) (*VTResult, error) {
	urlID := strings.TrimSpace(url)
	if urlID == "" {
		return nil, fmt.Errorf("empty URL")
	}

	cached, err := c.checkCache(ctx, "url:"+urlID)
	if err == nil && cached != nil {
		return cached, nil
	}

	if c.apiKey == "" {
		return &VTResult{
			Indicator:  url,
			Type:       "url",
			Reputation: "unknown",
			Error:      "VT API key not configured (set INNO_VT_API_KEY)",
		}, nil
	}

	c.rateLimit.Lock()
	elapsed := time.Since(c.lastCall)
	if elapsed < c.minInterval {
		time.Sleep(c.minInterval - elapsed)
	}
	c.lastCall = time.Now()
	c.rateLimit.Unlock()

	return c.fetchURLFromVT(ctx, urlID)
}

func (c *VTClient) LookupIP(ctx context.Context, ip string) (*VTResult, error) {
	ip = strings.TrimSpace(ip)

	cached, err := c.checkCache(ctx, "ip:"+ip)
	if err == nil && cached != nil {
		return cached, nil
	}

	if c.apiKey == "" {
		return &VTResult{
			Indicator:  ip,
			Type:       "ip",
			Reputation: "unknown",
			Error:      "VT API key not configured (set INNO_VT_API_KEY)",
		}, nil
	}

	c.rateLimit.Lock()
	elapsed := time.Since(c.lastCall)
	if elapsed < c.minInterval {
		time.Sleep(c.minInterval - elapsed)
	}
	c.lastCall = time.Now()
	c.rateLimit.Unlock()

	return c.fetchIPFromVT(ctx, ip)
}

func (c *VTClient) checkCache(ctx context.Context, key string) (*VTResult, error) {
	var data string
	err := c.cacheDB.QueryRowContext(ctx,
		`SELECT value FROM cache WHERE key = ? AND ttl > CAST(strftime('%s','now') AS INTEGER)`,
		"vt:"+key).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var result VTResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *VTClient) cacheResult(ctx context.Context, key string, result *VTResult) {
	data, _ := json.Marshal(result)
	c.cacheDB.ExecContext(ctx,
		`INSERT OR REPLACE INTO cache (key, value, ttl) VALUES (?, ?, CAST(strftime('%s','now') AS INTEGER) + ?)`,
		"vt:"+key, string(data), 3600)
}

func (c *VTClient) fetchFromVT(ctx context.Context, hash string) (*VTResult, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return &VTResult{Hash: hash, Indicator: hash, Type: "hash", Reputation: "unknown", Error: fmt.Sprintf("request error: %v", err)}, nil
	}

	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("User-Agent", "innoigniter/0.1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &VTResult{Hash: hash, Indicator: hash, Type: "hash", Reputation: "unknown", Error: fmt.Sprintf("VT unreachable: %v", err)}, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &VTResult{Hash: hash, Indicator: hash, Type: "hash", Reputation: "unknown", Error: fmt.Sprintf("read response: %v", err)}, nil
	}

	if resp.StatusCode == 404 {
		result := &VTResult{Hash: hash, Indicator: hash, Type: "hash", Reputation: "unknown", Total: 0, Error: "not found"}
		c.cacheResult(ctx, hash, result)
		return result, nil
	}

	if resp.StatusCode == 429 {
		return &VTResult{Hash: hash, Indicator: hash, Type: "hash", Reputation: "unknown", Error: "rate limited"}, nil
	}

	if resp.StatusCode != 200 {
		return &VTResult{Hash: hash, Indicator: hash, Type: "hash", Reputation: "unknown", Error: fmt.Sprintf("VT returned status %d", resp.StatusCode)}, nil
	}

	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats map[string]int `json:"last_analysis_stats"`
				LastAnalysisDate  int64          `json:"last_analysis_date"`
				TimesSubmitted    int            `json:"times_submitted"`
				LastAnalysisResults map[string]struct {
					Category string `json:"category"`
					Result   string `json:"result"`
				} `json:"last_analysis_results"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &vtResp); err != nil {
		return &VTResult{Hash: hash, Indicator: hash, Type: "hash", Reputation: "unknown", Error: fmt.Sprintf("parse response: %v", err)}, nil
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	result := &VTResult{
		Hash:       hash,
		Indicator:  hash,
		Type:       "hash",
		Malicious:  stats["malicious"],
		Suspicious: stats["suspicious"],
		Undetected: stats["undetected"],
		Total:      stats["malicious"] + stats["suspicious"] + stats["undetected"] + stats["harmless"],
	}

	if result.Malicious > 0 {
		result.Reputation = "malicious"
	} else if result.Suspicious > 0 {
		result.Reputation = "suspicious"
	} else {
		result.Reputation = "clean"
	}

	if vtResp.Data.Attributes.LastAnalysisDate > 0 {
		result.LastAnalysis = time.Unix(vtResp.Data.Attributes.LastAnalysisDate, 0).UTC().Format(time.RFC3339)
	}

	for _, v := range vtResp.Data.Attributes.LastAnalysisResults {
		if v.Result != "" && (v.Category == "malicious" || v.Category == "suspicious") && len(result.Vendors) < 10 {
			result.Vendors = append(result.Vendors, VTVerdict{Vendor: "", Result: v.Result, Category: v.Category})
		}
	}

	c.cacheResult(ctx, hash, result)
	return result, nil
}

func (c *VTClient) fetchURLFromVT(ctx context.Context, urlStr string) (*VTResult, error) {
	urlID := fmt.Sprintf("https://www.virustotal.com/api/v3/urls/%s", urlStr)
	req, err := http.NewRequestWithContext(ctx, "GET", urlID, nil)
	if err != nil {
		return &VTResult{Indicator: urlStr, Type: "url", Reputation: "unknown", Error: err.Error()}, nil
	}

	req.Header.Set("x-apikey", c.apiKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &VTResult{Indicator: urlStr, Type: "url", Reputation: "unknown", Error: fmt.Sprintf("VT unreachable: %v", err)}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return &VTResult{Indicator: urlStr, Type: "url", Reputation: "unknown", Error: fmt.Sprintf("VT returned %d", resp.StatusCode)}, nil
	}

	return &VTResult{Indicator: urlStr, Type: "url", Reputation: "unknown"}, nil
}

func (c *VTClient) fetchIPFromVT(ctx context.Context, ip string) (*VTResult, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return &VTResult{Indicator: ip, Type: "ip", Reputation: "unknown", Error: err.Error()}, nil
	}

	req.Header.Set("x-apikey", c.apiKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &VTResult{Indicator: ip, Type: "ip", Reputation: "unknown", Error: fmt.Sprintf("VT unreachable: %v", err)}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return &VTResult{Indicator: ip, Type: "ip", Reputation: "unknown", Error: fmt.Sprintf("VT returned %d", resp.StatusCode)}, nil
	}

	return &VTResult{Indicator: ip, Type: "ip", Reputation: "unknown"}, nil
}

func isValidHash(s string) bool {
	switch len(s) {
	case 32, 40, 64:
		for _, c := range s {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	return false
}
