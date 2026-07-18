package splunk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/yanmyoaung2004/innoigniter-ai/internal/agent"
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

func (a *Agent) Name() string { return "splunk" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "search", Inputs: []string{"url", "username", "password", "query"}, Outputs: []string{"results", "count"}},
		{Action: "saved_search", Inputs: []string{"url", "username", "password", "saved_search_name"}, Outputs: []string{"results", "count"}},
		{Action: "alert", Inputs: []string{"url", "token", "alert_name"}, Outputs: []string{"results", "count"}},
	}
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
	baseURL, _ := input["url"].(string)
	username, _ := input["username"].(string)
	password, _ := input["password"].(string)
	query, _ := input["query"].(string)

	if baseURL == "" || query == "" {
		return agent.Output{"error": "url and query are required", "count": 0}, nil
	}

	splURL := fmt.Sprintf("%s/services/search/jobs/export", stripTrailingSlash(baseURL))
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
	req.SetBasicAuth(username, password)

	resp, err := a.httpClient.Do(req)
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
	baseURL, _ := input["url"].(string)
	username, _ := input["username"].(string)
	password, _ := input["password"].(string)
	savedSearch, _ := input["saved_search_name"].(string)

	if baseURL == "" || savedSearch == "" {
		return agent.Output{"error": "url and saved_search_name are required", "count": 0}, nil
	}

	ssURL := fmt.Sprintf("%s/servicesNS/-/-/saved/searches/%s/history", stripTrailingSlash(baseURL), url.PathEscape(savedSearch))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ssURL, nil)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(username, password)

	resp, err := a.httpClient.Do(req)
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
	baseURL, _ := input["url"].(string)
	token, _ := input["token"].(string)
	alertName, _ := input["alert_name"].(string)

	if baseURL == "" {
		return agent.Output{"error": "url is required", "count": 0}, nil
	}

	alertURL := fmt.Sprintf("%s/services/alerts/fired_alerts", stripTrailingSlash(baseURL))
	if alertName != "" {
		alertURL = fmt.Sprintf("%s/%s", alertURL, url.PathEscape(alertName))
	}
	alertURL += "?output_mode=json&count=50"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, alertURL, nil)
	if err != nil {
		return agent.Output{"error": err.Error(), "count": 0}, nil
	}
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	resp, err := a.httpClient.Do(req)
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

func stripTrailingSlash(s string) string {
	if len(s) > 0 && s[len(s)-1] == '/' {
		return s[:len(s)-1]
	}
	return s
}
