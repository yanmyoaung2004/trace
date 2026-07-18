package elastic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/innoigniter/edge/internal/agent"
)

type Agent struct {
	httpClient *http.Client
}

func New() *Agent {
	return &Agent{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (a *Agent) Name() string { return "elastic" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "search", Inputs: []string{"url", "api_key", "index", "query"}, Outputs: []string{"hits", "count"}},
		{Action: "alert", Inputs: []string{"url", "api_key", "rule_id"}, Outputs: []string{"alerts", "count"}},
		{Action: "indices", Inputs: []string{"url", "api_key"}, Outputs: []string{"indices"}},
	}
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
	baseURL, _ := input["url"].(string)
	apiKey, _ := input["api_key"].(string)
	index, _ := input["index"].(string)
	queryStr, _ := input["query"].(string)

	if baseURL == "" {
		return agent.Output{"error": "url is required", "count": 0}, nil
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
	searchURL := fmt.Sprintf("%s/%s/_search", stripTrailingSlash(baseURL), index)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, searchURL, bytes.NewReader(data))
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", apiKey))
	}

	resp, err := a.httpClient.Do(req)
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
	baseURL, _ := input["url"].(string)
	apiKey, _ := input["api_key"].(string)
	ruleID, _ := input["rule_id"].(string)

	if baseURL == "" {
		return agent.Output{"error": "url is required", "count": 0}, nil
	}

	alertsURL := fmt.Sprintf("%s/_plugins/_security_analytics/alerts", stripTrailingSlash(baseURL))
	if ruleID != "" {
		alertsURL = fmt.Sprintf("%s?rule_id=%s", alertsURL, ruleID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, alertsURL, nil)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	if apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", apiKey))
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return agent.Output{"error": fmt.Sprintf("ES HTTP %d", resp.StatusCode), "count": 0}, nil
	}

	return agent.Output{
		"alerts":     string(body),
		"rule_id":    ruleID,
	}, nil
}

func (a *Agent) listIndices(ctx context.Context, input agent.Input) (agent.Output, error) {
	baseURL, _ := input["url"].(string)
	apiKey, _ := input["api_key"].(string)

	if baseURL == "" {
		return agent.Output{"error": "url is required"}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/_cat/indices?format=json&h=index,docs.count,store.size", stripTrailingSlash(baseURL)), nil)
	if err != nil {
		return agent.Output{"error": err.Error()}, nil
	}
	if apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", apiKey))
	}

	resp, err := a.httpClient.Do(req)
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
