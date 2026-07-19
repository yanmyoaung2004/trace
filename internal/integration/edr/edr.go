package edr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Provider     string `json:"provider"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	APIToken     string `json:"api_token,omitempty"`
	BaseURL      string `json:"base_url"`
	TenantID     string `json:"tenant_id,omitempty"`
}

type AgentInfo struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	Status     string `json:"status"`
	Platform   string `json:"platform"`
	IPAddress  string `json:"ip_address"`
	LastSeen   string `json:"last_seen"`
}

type ProcessInfo struct {
	PID      int    `json:"pid"`
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	User     string `json:"user,omitempty"`
	CPU      float64 `json:"cpu,omitempty"`
	MemoryMB int    `json:"memory_mb,omitempty"`
}

type EDRClient struct {
	config     Config
	client     *http.Client
	token      string
	tokenExp   time.Time
	mu         sync.Mutex
	rateLimit  *sync.Mutex
	lastCall   time.Time
	minInterval time.Duration
}

func New(config Config) *EDRClient {
	return &EDRClient{
		config:      config,
		client:      &http.Client{Timeout: 30 * time.Second},
		rateLimit:   &sync.Mutex{},
		minInterval: 200 * time.Millisecond,
	}
}

func (e *EDRClient) Name() string { return "edr_" + e.config.Provider }

func (e *EDRClient) authenticate(ctx context.Context) error {
	e.mu.Lock()
	if e.token != "" && time.Now().Before(e.tokenExp) {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()

	switch e.config.Provider {
	case "crowdstrike":
		return e.authCrowdStrike(ctx)
	case "sentinelone":
		return nil
	case "mde":
		return e.authMDE(ctx)
	default:
		return fmt.Errorf("unknown EDR provider: %s", e.config.Provider)
	}
}

func (e *EDRClient) authCrowdStrike(ctx context.Context) error {
	url := fmt.Sprintf("%s/oauth2/token", e.config.BaseURL)
	payload := []byte(fmt.Sprintf("client_id=%s&client_secret=%s", e.config.ClientID, e.config.ClientSecret))

	e.mu.Lock()
	e.rateLimit.Lock()
	e.mu.Unlock()

	resp, err := e.client.Post(url, "application/x-www-form-urlencoded", bytes.NewReader(payload))
	e.rateLimit.Unlock()
	if err != nil {
		return fmt.Errorf("crowdstrike auth: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("crowdstrike auth parse: %w", err)
	}
	if result.AccessToken == "" {
		return fmt.Errorf("crowdstrike auth failed: no token")
	}

	e.mu.Lock()
	e.token = result.AccessToken
	e.tokenExp = time.Now().Add(time.Duration(result.ExpiresIn-60) * time.Second)
	e.mu.Unlock()
	return nil
}

func (e *EDRClient) authMDE(ctx context.Context) error {
	url := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", e.config.TenantID)
	payload := []byte(fmt.Sprintf("client_id=%s&client_secret=%s&scope=https://api.securitycenter.microsoft.com/.default&grant_type=client_credentials",
		e.config.ClientID, e.config.ClientSecret))

	resp, err := e.client.Post(url, "application/x-www-form-urlencoded", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("mde auth: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("mde auth parse: %w", err)
	}

	e.mu.Lock()
	e.token = result.AccessToken
	e.tokenExp = time.Now().Add(time.Duration(result.ExpiresIn-60) * time.Second)
	e.mu.Unlock()
	return nil
}

func (e *EDRClient) doRequest(ctx context.Context, method, path string, body any) ([]byte, error) {
	if err := e.authenticate(ctx); err != nil {
		return nil, err
	}

	var url string
	if strings.HasPrefix(path, "http") {
		url = path
	} else {
		url = fmt.Sprintf("%s%s", e.config.BaseURL, path)
	}

	e.rateLimit.Lock()
	elapsed := time.Since(e.lastCall)
	if elapsed < e.minInterval {
		time.Sleep(e.minInterval - elapsed)
	}
	e.lastCall = time.Now()
	e.rateLimit.Unlock()

	var reqBody io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	token := e.token
	e.mu.Unlock()

	switch e.config.Provider {
	case "crowdstrike":
		req.Header.Set("Authorization", "Bearer "+token)
	case "sentinelone":
		req.Header.Set("Authorization", "APIToken "+e.config.APIToken)
	case "mde":
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "trace/0.2.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 429 {
		time.Sleep(5 * time.Second)
		return nil, fmt.Errorf("rate limited")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("EDR %s: HTTP %d — %s", e.config.Provider, resp.StatusCode, string(data[:min(len(data), 200)]))
	}

	return data, nil
}

func (e *EDRClient) GetAgentInfo(ctx context.Context, hostname string) (*AgentInfo, error) {
	switch e.config.Provider {
	case "crowdstrike":
		return e.getCSAgent(ctx, hostname)
	case "sentinelone":
		return e.getS1Agent(ctx, hostname)
	case "mde":
		return e.getMDEAgent(ctx, hostname)
	}
	return nil, fmt.Errorf("unsupported provider")
}

func (e *EDRClient) getCSAgent(ctx context.Context, hostname string) (*AgentInfo, error) {
	data, err := e.doRequest(ctx, "GET", fmt.Sprintf("/sensors/queries/devices/v1?filter=hostname:'%s'", hostname), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Resources []string `json:"resources"`
	}
	json.Unmarshal(data, &resp)
	if len(resp.Resources) == 0 {
		return nil, fmt.Errorf("host %q not found", hostname)
	}

	data, err = e.doRequest(ctx, "GET", fmt.Sprintf("/sensors/entities/devices/v1?ids=%s", strings.Join(resp.Resources, ",")), nil)
	if err != nil {
		return nil, err
	}

	var detail struct {
		Resources []struct {
			DeviceID   string `json:"device_id"`
			Hostname   string `json:"hostname"`
			Status     string `json:"status"`
			Platform   string `json:"platform_name"`
			LocalIP    string `json:"local_ip"`
			LastSeen   string `json:"last_seen"`
		} `json:"resources"`
	}
	json.Unmarshal(data, &detail)
	if len(detail.Resources) == 0 {
		return nil, fmt.Errorf("no details for %q", hostname)
	}

	d := detail.Resources[0]
	return &AgentInfo{
		ID:        d.DeviceID,
		Hostname:  d.Hostname,
		Status:    d.Status,
		Platform:  d.Platform,
		IPAddress: d.LocalIP,
		LastSeen:  d.LastSeen,
	}, nil
}

func (e *EDRClient) getS1Agent(ctx context.Context, hostname string) (*AgentInfo, error) {
	data, err := e.doRequest(ctx, "GET", fmt.Sprintf("/web/api/v2.1/agents?hostname=%s", hostname), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			ID       string `json:"id"`
			Name     string `json:"computerName"`
			Status   string `json:"networkStatus"`
			Platform string `json:"osType"`
			IP       string `json:"lastIpToMgmt"`
			Seen     string `json:"lastActiveDate"`
		} `json:"data"`
	}
	json.Unmarshal(data, &resp)
	if len(resp.Data) == 0 {
		return nil, fmt.Errorf("host %q not found", hostname)
	}
	d := resp.Data[0]
	return &AgentInfo{
		ID:        d.ID,
		Hostname:  d.Name,
		Status:    d.Status,
		Platform:  d.Platform,
		IPAddress: d.IP,
		LastSeen:  d.Seen,
	}, nil
}

func (e *EDRClient) getMDEAgent(ctx context.Context, hostname string) (*AgentInfo, error) {
	data, err := e.doRequest(ctx, "GET", fmt.Sprintf("/api/machines?$filter=computerDnsName eq '%s'", hostname), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"computerDnsName"`
			Status   string `json:"healthStatus"`
			Platform string `json:"osPlatform"`
			IPs      []string `json:"ipAddresses"`
			Seen     string `json:"lastSeen"`
		} `json:"value"`
	}
	json.Unmarshal(data, &resp)
	if len(resp.Value) == 0 {
		return nil, fmt.Errorf("host %q not found", hostname)
	}
	d := resp.Value[0]
	ips := ""
	if len(d.IPs) > 0 {
		ips = d.IPs[0]
	}
	return &AgentInfo{
		ID:        d.ID,
		Hostname:  d.Name,
		Status:    d.Status,
		Platform:  d.Platform,
		IPAddress: ips,
		LastSeen:  d.Seen,
	}, nil
}

func (e *EDRClient) IsolateHost(ctx context.Context, agentID string) (string, error) {
	switch e.config.Provider {
	case "crowdstrike":
		data, err := e.doRequest(ctx, "POST", "/sensors/entities/devices-actions/v1?action_name=contain", map[string]any{"ids": []string{agentID}})
		if err != nil {
			return "", err
		}
		var resp struct {
			Resources []struct {
				ID string `json:"id"`
			} `json:"resources"`
		}
		json.Unmarshal(data, &resp)
		if len(resp.Resources) > 0 {
			return resp.Resources[0].ID, nil
		}
		return "submitted", nil

	case "sentinelone":
		data, err := e.doRequest(ctx, "POST", "/web/api/v2.1/agents/actions/disconnect", map[string]any{"filter": map[string]any{"ids": []string{agentID}}})
		if err != nil {
			return "", err
		}
		var resp struct {
			Data struct {
				Affected int `json:"affected"`
			} `json:"data"`
		}
		json.Unmarshal(data, &resp)
		return fmt.Sprintf("isolated (affected: %d)", resp.Data.Affected), nil

	case "mde":
		data, err := e.doRequest(ctx, "POST", fmt.Sprintf("/api/machines/%s/isolate", agentID), map[string]any{"comment": "Isolated by Trace", "isolationType": "Full"})
		if err != nil {
			return "", err
		}
		var resp struct {
			ID string `json:"id"`
		}
		json.Unmarshal(data, &resp)
		return resp.ID, nil
	}
	return "", fmt.Errorf("unsupported provider")
}

func (e *EDRClient) ReleaseHost(ctx context.Context, agentID string) (string, error) {
	switch e.config.Provider {
	case "crowdstrike":
		_, err := e.doRequest(ctx, "POST", "/sensors/entities/devices-actions/v1?action_name=lift_containment", map[string]any{"ids": []string{agentID}})
		return "released", err
	case "sentinelone":
		data, err := e.doRequest(ctx, "POST", "/web/api/v2.1/agents/actions/connect", map[string]any{"filter": map[string]any{"ids": []string{agentID}}})
		if err != nil {
			return "", err
		}
		var resp struct {
			Data struct {
				Affected int `json:"affected"`
			} `json:"data"`
		}
		json.Unmarshal(data, &resp)
		return fmt.Sprintf("released (affected: %d)", resp.Data.Affected), nil
	case "mde":
		data, err := e.doRequest(ctx, "POST", fmt.Sprintf("/api/machines/%s/unisolate", agentID), map[string]any{"comment": "Released by Trace"})
		if err != nil {
			return "", err
		}
		var resp struct {
			ID string `json:"id"`
		}
		json.Unmarshal(data, &resp)
		return resp.ID, nil
	}
	return "", fmt.Errorf("unsupported provider")
}
