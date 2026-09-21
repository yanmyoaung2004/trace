package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
	"github.com/yanmyoaung2004/trace/internal/integration"
)

// Agent resolves all credentials from central config wired at construction
// (NewWithConfig); secrets are never accepted from LLM input params. Input
// carries only non-secret operational fields (index, query, rule_id). See
// internal/config for the TRACE_* bindings.
type Agent struct {
	httpClient *http.Client
	connector  *integration.Connector
	breaker    *integration.CircuitBreaker
	bulkhead   *integration.Bulkhead
	baseURL    string
	apiKey     string
}

// AgentConfig carries Elastic credentials from central config. Wire via
// cmd/trace root.go initRegistry; never populate from LLM input.
type AgentConfig struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
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
		apiKey:     cfg.APIKey,
	}
}

func (a *Agent) Name() string { return "elastic" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "search", Inputs: []string{"index", "query"}, Outputs: []string{"hits", "count"}},
		{Action: "alert", Inputs: []string{"rule_id"}, Outputs: []string{"alerts", "count"}},
		{Action: "indices", Inputs: []string{}, Outputs: []string{"indices"}},
	}
}

// rejectSecretInputs refuses credentials smuggled in via LLM input params.
// Secrets are config-wired at construction; accepting LLM-supplied creds
// would exfiltrate them through prompt/log pipelines.
func rejectSecretInputs(input agent.Input) *agent.Output {
	for _, k := range []string{"url", "api_key", "username", "password", "token"} {
		if _, ok := input[k]; ok {
			return &agent.Output{"error": "secret '" + k + "' must come from central config (NewWithConfig), not input params"}
		}
	}
	return nil
}

// do wires the shared breaker/bulkhead around one HTTP call.
func (a *Agent) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if a.breaker != nil && !a.breaker.Allow() {
		return nil, fmt.Errorf("elastic circuit open")
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
		return a.search(ctx, input)
	case "alert":
		return a.alerts(ctx, input)
	case "indices":
		return a.listIndices(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

type esQuery struct {
	Query map[string]any `json:"query"`
	Size  int            `json:"size"`
	Sort  []any          `json:"sort,omitempty"`
}

func (a *Agent) search(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}
	index, _ := input["index"].(string)
	queryStr, _ := input["query"].(string)

	if a.baseURL == "" {
		return agent.Output{"error": "elastic base_url is required (central config)", "count": 0}, nil
	}
	if index == "" {
		index = "_all"
	}
	if queryStr == "" {
		queryStr = `{"match_all":{}}`
	}

	var queryBody map[string]any
	if err := json.Unmarshal([]byte(queryStr), &queryBody); err != nil {
		queryBody = map[string]any{
			"query": map[string]any{
				"query_string": map[string]any{"query": queryStr},
			},
		}
	}

	q := esQuery{
		Query: queryBody,
		Size:  100,
		Sort:  []any{map[string]any{"@timestamp": map[string]string{"order": "desc"}}},
	}

	if q.Query == nil {
		q.Query = map[string]any{"match_all": map[string]any{}}
	}

	data, _ := json.Marshal(q)
	searchURL := fmt.Sprintf("%s/%s/_search", stripTrailingSlash(a.baseURL), index)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, searchURL, bytes.NewReader(data))
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", a.apiKey))
	}

	resp, err := a.do(ctx, req)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return agent.Output{"error": fmt.Sprintf("ES HTTP %d: %s", resp.StatusCode, string(body)), "count": 0}, nil
	}

	var result map[string]any
	json.Unmarshal(body, &result)

	hits := extractHits(result)

	return agent.Output{
		"hits":  hits,
		"count": len(hits),
		"raw":   string(body),
	}, nil
}

func (a *Agent) alerts(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}
	ruleID, _ := input["rule_id"].(string)

	if a.baseURL == "" {
		return agent.Output{"error": "elastic base_url is required (central config)", "count": 0}, nil
	}

	alertsURL := fmt.Sprintf("%s/_plugins/_security_analytics/alerts", stripTrailingSlash(a.baseURL))
	if ruleID != "" {
		alertsURL = fmt.Sprintf("%s?rule_id=%s", alertsURL, ruleID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, alertsURL, nil)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	if a.apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", a.apiKey))
	}

	resp, err := a.do(ctx, req)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return agent.Output{"error": fmt.Sprintf("ES HTTP %d", resp.StatusCode), "count": 0}, nil
	}

	return agent.Output{
		"alerts":  string(body),
		"rule_id": ruleID,
	}, nil
}

func (a *Agent) listIndices(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}

	if a.baseURL == "" {
		return agent.Output{"error": "elastic base_url is required (central config)"}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/_cat/indices?format=json&h=index,docs.count,store.size", stripTrailingSlash(a.baseURL)), nil)
	if err != nil {
		return agent.Output{"error": err.Error()}, nil
	}
	if a.apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", a.apiKey))
	}

	resp, err := a.do(ctx, req)
	if err != nil {
		return agent.Output{"error": err.Error()}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return agent.Output{"error": fmt.Sprintf("ES HTTP %d", resp.StatusCode)}, nil
	}

	var indices []map[string]any
	json.Unmarshal(body, &indices)

	return agent.Output{
		"indices": indices,
		"count":   len(indices),
	}, nil
}

// SetTestURL overrides the base URL for httptest servers. Tests only.
func (a *Agent) SetTestURL(rawurl string) { a.baseURL = rawurl }

func extractHits(result map[string]any) []map[string]any {
	hitsRoot, _ := result["hits"].(map[string]any)
	if hitsRoot == nil {
		return nil
	}
	hits, _ := hitsRoot["hits"].([]any)
	if hits == nil {
		return nil
	}
	var out []map[string]any
	for _, h := range hits {
		if hit, ok := h.(map[string]any); ok {
			source, _ := hit["_source"].(map[string]any)
			if source != nil {
				source["_id"] = hit["_id"]
				source["_index"] = hit["_index"]
				source["_score"] = hit["_score"]
				out = append(out, source)
			}
		}
	}
	return out
}

func stripTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
