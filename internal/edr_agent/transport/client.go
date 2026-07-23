package transport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yanmyoaung2004/trace/internal/edr_agent/monitor"
)

type Config struct {
	ServerURL   string
	APIKey      string
	AgentID     string
	TLSCertFile string
	TLSKeyFile  string
	CAFile      string
	Timeout     time.Duration
	RetryMax    int
	RetryBase   time.Duration
}

type Client struct {
	config  *Config
	client  *http.Client
	mu      sync.Mutex
	agentID string
}

type RegisterRequest struct {
	Hostname      string `json:"hostname"`
	Platform      string `json:"platform"`
	Arch          string `json:"arch"`
	Version       string `json:"version"`
	KernelVersion string `json:"kernel_version,omitempty"`
	CPUCount      int    `json:"cpu_count"`
	CPUName       string `json:"cpu_name,omitempty"`
	MemoryMB      int64  `json:"memory_mb"`
	AgentVersion  string `json:"agent_version"`
	Monitors      string `json:"monitors"`
}

type RegisterResponse struct {
	AgentID string `json:"agent_id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type Heartbeat struct {
	AgentID  string     `json:"agent_id"`
	Hostname string     `json:"hostname"`
	Status   string     `json:"status"`
	Version  string     `json:"version"`
	Uptime   int64      `json:"uptime"`
	Stats    AgentStats `json:"stats"`
}

type AgentStats struct {
	EventsCollected int64   `json:"events_collected"`
	EventsSent      int64   `json:"events_sent"`
	ActionsExecuted int64   `json:"actions_executed"`
	ActionsFailed   int64   `json:"actions_failed"`
	CPUPercent      float64 `json:"cpu_percent"`
	MemoryMB        int64   `json:"memory_mb"`
}

type PendingAction struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Target   string            `json:"target,omitempty"`
	Params   map[string]any    `json:"params,omitempty"`
	Timeout  int               `json:"timeout_seconds"`
}

type ActionResult struct {
	AgentID  string         `json:"agent_id"`
	ActionID string         `json:"action_id"`
	Status   string         `json:"status"`
	Error    string         `json:"error,omitempty"`
	Output   map[string]any `json:"output,omitempty"`
	ExecutedAt string       `json:"executed_at"`
}

func NewClient(cfg *Config) *Client {
	t := &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	// mTLS: Load client and CA certificates
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Printf("[transport] mTLS cert load failed: %v (falling back to HTTPS)", err)
		} else {
			tlsCfg := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}

			if cfg.CAFile != "" {
				caCert, err := os.ReadFile(cfg.CAFile)
				if err != nil {
					log.Printf("[transport] CA load failed: %v", err)
				} else {
					caPool := x509.NewCertPool()
					caPool.AppendCertsFromPEM(caCert)
					tlsCfg.RootCAs = caPool
				}
			}

			t.TLSClientConfig = tlsCfg
			log.Printf("[transport] mTLS configured (cert: %s)", cfg.TLSCertFile)
		}
	}

	return &Client{
		config: cfg,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: t,
		},
		agentID: cfg.AgentID,
	}
}

func (c *Client) SetAgentID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.agentID = id
}

func (c *Client) baseURL() string {
	url := strings.TrimRight(c.config.ServerURL, "/")
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}
	return url
}

func (c *Client) signRequest(body []byte) string {
	if c.config.APIKey == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(c.config.APIKey))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reqBody []byte
	var err error
	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
	}

	url := c.baseURL() + path
	var lastErr error

	for attempt := 0; attempt <= c.config.RetryMax; attempt++ {
		if attempt > 0 {
			backoff := c.config.RetryBase * time.Duration(math.Pow(2, float64(attempt-1)))
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			time.Sleep(backoff)
		}

		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "trace-agent/0.1.1")

		if c.config.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
			if len(reqBody) > 0 {
				req.Header.Set("X-Signature", c.signRequest(reqBody))
			}
		}

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("http: %w", err)
			continue
		}
		defer resp.Body.Close()

		data, _ := io.ReadAll(resp.Body)

		if resp.StatusCode == 429 {
			lastErr = fmt.Errorf("rate limited")
			time.Sleep(5 * time.Second)
			continue
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error: HTTP %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("request failed: HTTP %d — %s", resp.StatusCode, string(data))
		}

		return data, nil
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", c.config.RetryMax, lastErr)
}

func (c *Client) Register(ctx context.Context, info *RegisterRequest) (*RegisterResponse, error) {
	data, err := c.do(ctx, "POST", "/api/v1/edr/register", info)
	if err != nil {
		return nil, err
	}
	var resp RegisterResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &resp, nil
}

func (c *Client) Heartbeat(ctx context.Context, hb *Heartbeat) error {
	_, err := c.do(ctx, "POST", "/api/v1/edr/heartbeat", hb)
	return err
}

func (c *Client) SendEvents(ctx context.Context, agentID string, events []*monitor.Event) error {
	body := map[string]any{
		"agent_id": agentID,
		"events":   events,
	}
	_, err := c.do(ctx, "POST", "/api/v1/edr/events", body)
	return err
}

func (c *Client) PollActions(ctx context.Context, agentID string) ([]*PendingAction, error) {
	data, err := c.do(ctx, "GET", fmt.Sprintf("/api/v1/edr/actions/pending?agent_id=%s", agentID), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Actions []*PendingAction `json:"actions"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse actions: %w", err)
	}
	return resp.Actions, nil
}

func (c *Client) ReportActionResult(ctx context.Context, agentID, actionID, status, errMsg string, output map[string]any) error {
	body := &ActionResult{
		AgentID:    agentID,
		ActionID:   actionID,
		Status:     status,
		Error:      errMsg,
		Output:     output,
		ExecutedAt: time.Now().UTC().Format(time.RFC3339),
	}
	_, err := c.do(ctx, "POST", "/api/v1/edr/actions/result", body)
	return err
}
