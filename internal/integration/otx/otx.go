package otx

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type Client struct {
	apiKey     string
	httpClient *http.Client
}

func New(apiKey string) *Client {
	return &Client{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

type OTXIndicator struct {
	Type        string `json:"type"`
	Indicator   string `json:"indicator"`
	Description string `json:"description"`
	PulseCount  int    `json:"pulse_info"`
}

type OTXPulse struct {
	Count int `json:"count"`
}

type OTXResponse struct {
	PulseInfo OTXPulse `json:"pulse_info"`
}

func (c *Client) CheckIndicator(ctx context.Context, indicator string) (*OTXResponse, error) {
	if c.apiKey == "" {
		return nil, nil
	}

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/ip/%s/general", indicator)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("otx request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otx HTTP %d", resp.StatusCode)
	}

	var result OTXResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("otx decode: %w", err)
	}
	return &result, nil
}

type Agent struct {
	client *Client
}

func NewAgent(apiKey string) *Agent {
	return &Agent{client: New(apiKey)}
}

func (a *Agent) Name() string { return "otx" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "indicator_check", Inputs: []string{"indicator"}, Outputs: []string{"pulse_count", "reputation"}},
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
		"indicator":   indicator,
		"reputation":  reputation,
		"confidence":  confidence,
		"pulse_count": data.PulseInfo.Count,
	}, nil
}
