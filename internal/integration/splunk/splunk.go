package splunk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
	"github.com/yanmyoaung2004/trace/internal/integration"
)

// Agent resolves all credentials from central config wired at construction
// (NewWithConfig); secrets are never accepted from LLM input params. Input
// carries only non-secret operational fields (query, saved_search_name,
// alert_name, index). See internal/config for the TRACE_* bindings.
type Agent struct {
	httpClient *http.Client
	connector  *integration.Connector
	breaker    *integration.CircuitBreaker
	bulkhead   *integration.Bulkhead
	baseURL    string
	username   string
	password   string
	token      string
}

// AgentConfig carries Splunk credentials from central config. Wire via
// cmd/trace root.go initRegistry; never populate from LLM input.
type AgentConfig struct {
	BaseURL  string `json:"base_url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

func New() *Agent {
	return &Agent{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		breaker:    integration.NewCircuitBreaker(5, 30*time.Second),
		bulkhead:   integration.NewBulkhead(8),
	}
}

// NewWithConfig wires config-supplied credentials; input params can never
// override them (secret inputs are rejected, not merged).
func NewWithConfig(cfg AgentConfig) *Agent {
	return &Agent{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		connector:  integration.NewConnector(integration.ConnectorConfig{BaseURL: cfg.BaseURL}),
		breaker:    integration.NewCircuitBreaker(5, 30*time.Second),
		bulkhead:   integration.NewBulkhead(8),
		baseURL:    cfg.BaseURL,
		username:   cfg.Username,
		password:   cfg.Password,
		token:      cfg.Token,
	}
}

func (a *Agent) Name() string { return "splunk" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "search", Inputs: []string{"query"}, Outputs: []string{"results", "count"}},
		{Action: "saved_search", Inputs: []string{"saved_search_name"}, Outputs: []string{"results", "count"}},
		{Action: "alert", Inputs: []string{"alert_name"}, Outputs: []string{"results", "count"}},
	}
}

// rejectSecretInputs refuses credentials smuggled in via LLM input params.
// Secrets are config-wired at construction; accepting LLM-supplied creds
// would exfiltrate them through prompt/log pipelines.
func rejectSecretInputs(input agent.Input) *agent.Output {
	for _, k := range []string{"url", "username", "password", "token", "api_key"} {
		if _, ok := input[k]; ok {
			return &agent.Output{"error": "secret '" + k + "' must come from central config (NewWithConfig), not input params", "count": 0}
		}
	}
	return nil
}

// do wires the shared breaker/bulkhead around one HTTP call.
func (a *Agent) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if a.breaker != nil && !a.breaker.Allow() {
		return nil, fmt.Errorf("splunk circuit open")
	}
	var resp *http.Response
	var callErr error
	run := func(ctx context.Context) error {
		var err error
		resp, err = a.httpClient.Do(req.WithContext(ctx))
		return err
	}
	if a.bulkhead != nil {
		callErr = a.bulkhead.Run(ctx, run)
	} else {
		callErr = run(ctx)
	}
	if a.breaker != nil {
		a.breaker.Record(callErr == nil)
	}
	return resp, callErr
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "search":
		return a.runSearch(ctx, input)
	case "saved_search":
		return a.runSavedSearch(ctx, input)
	case "alert":
		return a.checkAlert(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) runSearch(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}
	query, _ := input["query"].(string)

	if a.baseURL == "" {
		return agent.Output{"error": "splunk base_url is required (central config)", "count": 0}, nil
	}
	if query == "" {
		return agent.Output{"error": "query is required", "count": 0}, nil
	}

	splURL := fmt.Sprintf("%s/services/search/jobs/export", stripTrailingSlash(a.baseURL))
	data := url.Values{}
	data.Set("search", fmt.Sprintf("search %s", query))
	data.Set("output_mode", "json")
	data.Set("earliest_time", "-24h")
	data.Set("latest_time", "now")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, splURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.username, a.password)

	resp, err := a.do(ctx, req)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return agent.Output{"error": fmt.Sprintf("Splunk HTTP %d", resp.StatusCode), "count": 0}, nil
	}

	var results []map[string]any
	lines := bytes.Split(body, []byte("\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err == nil {
			if _, ok := entry["_raw"]; ok {
				results = append(results, entry)
			}
		}
	}

	return agent.Output{
		"results": results,
		"count":   len(results),
		"query":   query,
	}, nil
}
func (a *Agent) runSavedSearch(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}
	savedSearch, _ := input["saved_search_name"].(string)

	if a.baseURL == "" {
		return agent.Output{"error": "splunk base_url is required (central config)", "count": 0}, nil
	}
	if savedSearch == "" {
		return agent.Output{"error": "saved_search_name is required", "count": 0}, nil
	}

	ssURL := fmt.Sprintf("%s/servicesNS/-/-/saved/searches/%s/history", stripTrailingSlash(a.baseURL), url.PathEscape(savedSearch))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ssURL, nil)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.username, a.password)

	resp, err := a.do(ctx, req)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return agent.Output{"error": fmt.Sprintf("Splunk HTTP %d", resp.StatusCode), "count": 0}, nil
	}

	return agent.Output{
		"saved_search": savedSearch,
		"count":        1,
	}, nil
}

func (a *Agent) checkAlert(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}
	alertName, _ := input["alert_name"].(string)

	if a.baseURL == "" {
		return agent.Output{"error": "splunk base_url is required (central config)", "count": 0}, nil
	}

	alertURL := fmt.Sprintf("%s/services/alerts/fired_alerts", stripTrailingSlash(a.baseURL))
	if alertName != "" {
		alertURL = fmt.Sprintf("%s/%s", alertURL, url.PathEscape(alertName))
	}
	alertURL += "?output_mode=json&count=50"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, alertURL, nil)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	if a.token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.token))
	}

	resp, err := a.do(ctx, req)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return agent.Output{"error": fmt.Sprintf("Splunk HTTP %d", resp.StatusCode), "count": 0}, nil
	}

	var parsed map[string]any
	json.Unmarshal(body, &parsed)

	return agent.Output{
		"alert_name": alertName,
		"raw":        string(body),
		"parsed":     parsed,
	}, nil
}

// SetTestURL overrides the base URL for httptest servers. Tests only.
func (a *Agent) SetTestURL(rawurl string) { a.baseURL = rawurl }

func stripTrailingSlash(s string) string {
	if len(s) > 0 && s[len(s)-1] == '/' {
		return s[:len(s)-1]
	}
	return s
}
