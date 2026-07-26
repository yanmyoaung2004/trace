package dispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
	"github.com/yanmyoaung2004/trace/internal/playbook"
	_ "modernc.org/sqlite"
)

type Agent struct {
	playbooks   *playbook.Engine
	planner     *LLMPlanner
	httpClient  *http.Client
}

func New(playbooks *playbook.Engine) *Agent {
	return &Agent{
		playbooks:  playbooks,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *Agent) WithPlanner(provider, url, apiKey string) *LLMPlanner {
	a.planner = NewLLMPlanner(provider, url, apiKey)
	return a.planner
}

func (a *Agent) Name() string { return "dispatch" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "synthesize_report", Inputs: []string{"results", "investigation_id"}, Outputs: []string{"report", "confidence", "summary"}},
		{Action: "plan_investigation", Inputs: []string{"intent"}, Outputs: []string{"playbook", "parameters"}},
		{Action: "classify_intent", Inputs: []string{"query"}, Outputs: []string{"playbook", "confidence"}},
		{Action: "calculate_confidence", Inputs: []string{"results"}, Outputs: []string{"confidence", "factors"}},
	}
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "synthesize_report":
		return a.synthesizeReport(ctx, input)
	case "plan_investigation":
		return a.planInvestigation(ctx, input)
	case "classify_intent":
		return a.classifyIntent(ctx, input)
	case "calculate_confidence":
		return a.calculateConfidence(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) synthesizeReport(_ context.Context, input agent.Input) (agent.Output, error) {
	results, _ := input["results"].(map[string]any)
	intent, _ := input["intent"].(string)
	investigationID, _ := input["investigation_id"].(string)

	confidence := a.calculateConfidenceFromResults(results)
	summary := a.generateSummary(results)
	findings := a.extractFindings(results)
	indicators := a.extractIndicators(results)

	report := formatMarkdownReport(intent, investigationID, confidence, summary, findings, indicators, results)

	return agent.Output{
		"report":        report,
		"confidence":    confidence,
		"summary":       summary,
		"findings":      findings,
		"indicators":    indicators,
		"investigation_id": investigationID,
		"status":        "ok",
	}, nil
}

func (a *Agent) planInvestigation(ctx context.Context, input agent.Input) (agent.Output, error) {
	intent, _ := input["intent"].(string)
	if intent == "" {
		return nil, fmt.Errorf("intent is required")
	}

	playbookName := pickPlaybook(intent, a.playbooks, input)

	if playbookName == "" || playbookName == "hash-lookup" {
		if a.planner != nil {
			availablePlaybooks := make([]string, 0, len(a.playbooks.List()))
			for _, pb := range a.playbooks.List() {
				availablePlaybooks = append(availablePlaybooks, pb.Name)
			}

			llmName, llmParams, llmErr := a.planner.Plan(ctx, intent, availablePlaybooks)

			if llmErr != nil {
				log.Printf("[dispatch] LLM plan failed: %v (falling back to heuristic)", llmErr)
			}

			if llmErr == nil && llmName != "" {
				if pb := a.playbooks.Get(llmName); pb != nil {
					if llmParams == nil {
						llmParams = extractParams(intent, pb)
					}
					return agent.Output{
						"playbook":   pb.Name,
						"parameters": llmParams,
						"planner":    "llm",
					}, nil
				}
			}
		}

		if playbookName == "" {
			playbookName = "hash-lookup"
		}
	}

	pb := a.playbooks.Get(playbookName)
	if pb == nil {
		return agent.Output{"playbook": "hash-lookup", "parameters": input}, nil
	}

	params := extractParams(intent, pb)

	return agent.Output{
		"playbook":   pb.Name,
		"parameters": params,
		"planner":    "heuristic",
	}, nil
}

func (a *Agent) classifyIntent(_ context.Context, input agent.Input) (agent.Output, error) {
	query, _ := input["query"].(string)

	pbName := pickPlaybook(query, a.playbooks, input)

	return agent.Output{
		"playbook":   pbName,
		"confidence": 0.8,
	}, nil
}

func (a *Agent) calculateConfidence(_ context.Context, input agent.Input) (agent.Output, error) {
	results, _ := input["results"].(map[string]any)
	confidence := a.calculateConfidenceFromResults(results)
	factors := a.confidenceFactors(results)

	return agent.Output{
		"confidence": confidence,
		"factors":    factors,
	}, nil
}

type llmCacheEntry struct {
	playbook   string
	parameters map[string]any
	timestamp  time.Time
}

// LLMProvider holds the configuration for a single LLM provider.
type LLMProvider struct {
	Name   string // "openai", "anthropic", "ollama"
	URL    string
	APIKey string
	Model  string
}

// ProgressFunc is called during Plan() to report progress stages to the caller.
// stage is one of: "cache_hit", "calling", "retry", "fallback", "failed"
// detail provides additional context (provider name, attempt number, etc.)
type ProgressFunc func(stage, detail string)

type LLMPlanner struct {
	providers []*LLMProvider // tried in order; primary is first
	client    *http.Client

	// cache
	cache     map[string]*llmCacheEntry
	cacheMu   sync.Mutex
	cacheSize int

	// counters (for cost tracking)
	TotalCalls    atomic.Int64
	CacheHits     atomic.Int64
	TotalFailures atomic.Int64

	// progress reporting
	progressFn ProgressFunc

	// persistent cache (optional SQLite)
	cacheDB *sql.DB
}

// SetProgressFunc registers a callback called during Plan() to report progress.
func (lp *LLMPlanner) SetProgressFunc(fn ProgressFunc) {
	lp.progressFn = fn
}

// WithCacheDB attaches a SQLite database for persistent LLM response caching.
// The cache survives restarts. Entries are evicted based on TTL (10min in-memory, 24h in SQLite).
func (lp *LLMPlanner) WithCacheDB(db *sql.DB) *LLMPlanner {
	lp.cacheDB = db
	lp.initCacheTable()
	return lp
}

func (lp *LLMPlanner) initCacheTable() {
	if lp.cacheDB == nil {
		return
	}
	lp.cacheDB.Exec(`CREATE TABLE IF NOT EXISTS llm_cache (
		key TEXT PRIMARY KEY,
		playbook TEXT NOT NULL,
		params TEXT NOT NULL DEFAULT '{}',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
}

func (lp *LLMPlanner) cacheGetFromDB(key string) (string, map[string]any, bool) {
	if lp.cacheDB == nil {
		return "", nil, false
	}
	var playbook, paramsJSON string
	err := lp.cacheDB.QueryRow(
		`SELECT playbook, params FROM llm_cache WHERE key = ? AND created_at > datetime('now', '-24 hours')`, key,
	).Scan(&playbook, &paramsJSON)
	if err != nil {
		return "", nil, false
	}
	var params map[string]any
	json.Unmarshal([]byte(paramsJSON), &params)
	return playbook, params, true
}

func (lp *LLMPlanner) cacheSetToDB(key, playbook string, params map[string]any) {
	if lp.cacheDB == nil {
		return
	}
	paramsJSON, _ := json.Marshal(params)
	lp.cacheDB.Exec(
		`INSERT OR REPLACE INTO llm_cache (key, playbook, params, created_at) VALUES (?, ?, ?, datetime('now'))`,
		key, playbook, string(paramsJSON),
	)
}

func (lp *LLMPlanner) reportProgress(stage, detail string) {
	if lp.progressFn != nil {
		lp.progressFn(stage, detail)
	}
}

const maxCacheSize = 100
const cacheTTL = 10 * time.Minute

// currentPromptVersion is incremented whenever the LLM prompt template changes.
// This invalidates old cached responses so users don't get stale results
// from a previous prompt version.
const currentPromptVersion = 1

// NewLLMPlanner creates a planner with a single primary provider.
// Use AddProvider to add fallback providers.
func NewLLMPlanner(provider, url, apiKey string) *LLMPlanner {
	return &LLMPlanner{
		providers: []*LLMProvider{{Name: provider, URL: url, APIKey: apiKey}},
		client:    &http.Client{Timeout: 30 * time.Second},
		cache:     make(map[string]*llmCacheEntry),
		cacheSize: maxCacheSize,
	}
}

func (lp *LLMPlanner) WithModel(model string) *LLMPlanner {
	if len(lp.providers) > 0 {
		lp.providers[0].Model = model
	}
	return lp
}

// AddProvider adds a fallback provider tried after the primary.
func (lp *LLMPlanner) AddProvider(name, url, apiKey, model string) *LLMPlanner {
	lp.providers = append(lp.providers, &LLMProvider{
		Name: name, URL: url, APIKey: apiKey, Model: model,
	})
	return lp
}

// Stats returns operational counters for monitoring LLM usage and cost.
func (lp *LLMPlanner) Stats() map[string]any {
	return map[string]any{
		"total_calls":    lp.TotalCalls.Load(),
		"cache_hits":     lp.CacheHits.Load(),
		"total_failures": lp.TotalFailures.Load(),
		"cache_size":     len(lp.cache),
	}
}

// cacheKey generates a hash of the intent + playbooks + prompt version for cache lookup.
// Includes promptVersion so that prompt template changes invalidate old cache entries.
func cacheKey(intent string, playbooks []string) string {
	version := fmt.Sprintf("v%d", currentPromptVersion)
	h := sha256.Sum256([]byte(version + intent + strings.Join(playbooks, ",")))
	return hex.EncodeToString(h[:16])
}

// getCached returns a cached LLM response if available and fresh.
// Checks in-memory cache first, then SQLite cache if configured.
func (lp *LLMPlanner) getCached(key string) (string, map[string]any, bool) {
	lp.cacheMu.Lock()
	defer lp.cacheMu.Unlock()

	// Check in-memory cache first
	entry, ok := lp.cache[key]
	if ok {
		if time.Since(entry.timestamp) > cacheTTL {
			delete(lp.cache, key)
		} else {
			return entry.playbook, entry.parameters, true
		}
	}

	// Check SQLite cache on miss (loads into in-memory cache)
	if pb, params, ok := lp.cacheGetFromDB(key); ok {
		lp.cache[key] = &llmCacheEntry{
			playbook:   pb,
			parameters: params,
			timestamp:  time.Now(),
		}
		return pb, params, true
	}

	return "", nil, false
}

// setCached stores an LLM response in both in-memory and SQLite caches.
func (lp *LLMPlanner) setCached(key, playbook string, params map[string]any) {
	lp.cacheMu.Lock()
	defer lp.cacheMu.Unlock()

	// In-memory cache
	if len(lp.cache) >= lp.cacheSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range lp.cache {
			if oldestKey == "" || v.timestamp.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.timestamp
			}
		}
		delete(lp.cache, oldestKey)
	}
	lp.cache[key] = &llmCacheEntry{
		playbook:   playbook,
		parameters: params,
		timestamp:  time.Now(),
	}

	// SQLite cache (async, non-blocking)
	lp.cacheSetToDB(key, playbook, params)
}

type openAIChoice struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

type openAIResp struct {
	Choices []openAIChoice `json:"choices"`
}

type anthropicResp struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

func (lp *LLMPlanner) Plan(ctx context.Context, intent string, availablePlaybooks []string) (string, map[string]any, error) {
	if len(lp.providers) == 0 || lp.providers[0].URL == "" {
		return "", nil, fmt.Errorf("LLM planner not configured (set TRACE_LLM_URL)")
	}

	// Check cache
	key := cacheKey(intent, availablePlaybooks)
	if cachedPb, cachedParams, ok := lp.getCached(key); ok {
		lp.CacheHits.Add(1)
		lp.reportProgress("cache_hit", "")
		log.Printf("[llm] cache hit for intent %q", intent[:min(len(intent), 60)])
		return cachedPb, cachedParams, nil
	}

	// Build prompt
	prompt := fmt.Sprintf(`You are a cybersecurity investigation planner. Given the user's intent, select the best playbook from: %s.
Return ONLY valid JSON: {"playbook": "name", "parameters": {"key": "value"}}
If no playbook matches, return {"playbook": "", "parameters": {}}.
Intent: %s`, strings.Join(availablePlaybooks, ", "), intent)

	// Try each provider in order, with retries per provider
	var lastErr error
	for pi, p := range lp.providers {
		if pi > 0 {
			lp.reportProgress("fallback", p.Name)
			log.Printf("[llm] primary provider failed, trying fallback %s", p.Name)
		}
		for attempt := 0; attempt < 2; attempt++ {
			lp.TotalCalls.Add(1)
			lp.reportProgress("calling", fmt.Sprintf("%s (attempt %d)", p.Name, attempt+1))

			llmCtx, llmCancel := context.WithTimeout(ctx, 10*time.Second)
			pbName, params, err := lp.callLLM(llmCtx, prompt, p)
			llmCancel()

			if err == nil {
				lp.setCached(key, pbName, params)
				return pbName, params, nil
			}

			lastErr = err
			lp.reportProgress("retry", fmt.Sprintf("%s attempt %d: %v", p.Name, attempt+1, err))
			log.Printf("[llm] provider=%s attempt %d failed: %v", p.Name, attempt+1, err)
		}

		// If there's another provider to try, skip the retry delay — move to next provider
		if pi+1 < len(lp.providers) {
			continue
		}

		// Last provider: retry with delay
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
	}

	lp.TotalFailures.Add(1)
	lp.reportProgress("failed", lastErr.Error())
	log.Printf("[llm] all providers failed for intent %q: %v (falling back to heuristic)", intent[:min(len(intent), 60)], lastErr)
	return "", nil, lastErr
}

// callLLM makes a single LLM API call to the given provider and parses the response.
func (lp *LLMPlanner) callLLM(ctx context.Context, prompt string, p *LLMProvider) (string, map[string]any, error) {
	var payload []byte
	var err error

	switch p.Name {
	case "anthropic":
		payload, err = lp.buildAnthropicPayload(p, prompt)
	case "ollama":
		payload, err = lp.buildOllamaPayload(p, prompt)
	default:
		payload, err = lp.buildOpenAIPayload(p, prompt)
	}
	if err != nil {
		return "", nil, fmt.Errorf("build payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.URL, bytes.NewReader(payload))
	if err != nil {
		return "", nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	switch p.Name {
	case "anthropic":
		req.Header.Set("x-api-key", p.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	case "ollama":
	default:
		if p.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.APIKey)
		}
	}

	resp, err := lp.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("llm request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("llm returned HTTP %d: %s", resp.StatusCode, string(respBody[:min(len(respBody), 200)]))
	}

	content := lp.extractContent(respBody)
	if content == "" {
		snippet := string(respBody)
		if len(snippet) > 500 {
			snippet = snippet[:500]
		}
		log.Printf("[llm] empty content from provider=%s (raw: %s)", p.Name, snippet)
		return "", nil, fmt.Errorf("llm returned empty response")
	}

	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var result struct {
		Playbook   string         `json:"playbook"`
		Parameters map[string]any `json:"parameters"`
	}
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		snippet := content
		if len(snippet) > 500 {
			snippet = snippet[:500]
		}
		log.Printf("[llm] json parse error for provider=%s: %v (content: %s)", p.Name, err, snippet)
		return "", nil, fmt.Errorf("parse llm response: %w", err)
	}

	if result.Playbook == "" {
		log.Printf("[llm] empty playbook from provider=%s (content: %s)", p.Name, content[:min(len(content), 200)])
		return "", nil, fmt.Errorf("llm didn't select a playbook")
	}

	return result.Playbook, result.Parameters, nil
}

func (lp *LLMPlanner) buildOpenAIPayload(p *LLMProvider, prompt string) ([]byte, error) {
	model := p.Model
	if model == "" {
		model = "gpt-4"
	}
	body := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You select playbooks and extract parameters from security investigation requests. Return only JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.1,
		"max_tokens":  300,
	}
	return json.Marshal(body)
}

func (lp *LLMPlanner) buildAnthropicPayload(p *LLMProvider, prompt string) ([]byte, error) {
	model := p.Model
	if model == "" {
		model = "claude-3-haiku-20240307"
	}
	body := map[string]any{
		"model":      model,
		"max_tokens": 300,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	return json.Marshal(body)
}

func (lp *LLMPlanner) buildOllamaPayload(p *LLMProvider, prompt string) ([]byte, error) {
	model := p.Model
	if model == "" {
		model = "llama3"
	}
	body := map[string]any{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}
	return json.Marshal(body)
}

func (lp *LLMPlanner) extractContent(body []byte) string {
	var openAI openAIResp
	if json.Unmarshal(body, &openAI) == nil && len(openAI.Choices) > 0 {
		return openAI.Choices[0].Message.Content
	}

	var anthropic anthropicResp
	if json.Unmarshal(body, &anthropic) == nil && len(anthropic.Content) > 0 {
		return anthropic.Content[0].Text
	}

	var ollama struct {
		Response string `json:"response"`
	}
	if json.Unmarshal(body, &ollama) == nil && ollama.Response != "" {
		return ollama.Response
	}

	return ""
}

func (a *Agent) calculateConfidenceFromResults(results map[string]any) float64 {
	if len(results) == 0 {
		return 0
	}

	scores := make([]float64, 0, len(results))
	for key, val := range results {
		resultMap, ok := val.(map[string]any)
		if !ok {
			continue
		}
		scores = append(scores, scoreResult(key, resultMap))
	}

	if len(scores) == 0 {
		return 0
	}

	total := 0.0
	for _, s := range scores {
		total += s
	}
	return total / float64(len(scores))
}

func getFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

func getInt(v any) int {
	return int(getFloat(v))
}

func scoreResult(key string, result map[string]any) float64 {
	reputation, _ := result["reputation"].(string)
	if reputation == "malicious" {
		return 0.95
	}
	if reputation == "suspicious" {
		return 0.7
	}

	maliciousV, hasMal := result["malicious"]
	if hasMal {
		mal := getFloat(maliciousV)
		if mal > 0 {
			total := getFloat(result["total"])
			if total > 0 && mal/total > 0.3 {
				return 0.9
			}
		}
	}

	if getFloat(result["count"]) > 0 {
		return 0.85
	}

	if foundV, ok := result["found"].(bool); ok && foundV {
		return 0.75
	}

	if suspiciousList, ok := result["suspicious"].([]any); ok && len(suspiciousList) > 0 {
		return 0.8
	}

	if intel, ok := result["intel"].(map[string]any); ok {
		if builtin, ok := intel["builtin_match"].(bool); ok && builtin {
			conf := getFloat(intel["confidence"])
			if conf > 0 {
				return conf
			}
			return 0.8
		}
	}

	errorStr, hasError := result["error"].(string)
	if hasError && errorStr != "" {
		if strings.Contains(errorStr, "not configured") {
			return 0
		}
		return 0.1
	}

	return 0.5
}

func (a *Agent) confidenceFactors(results map[string]any) map[string]float64 {
	factors := make(map[string]float64)
	for key, val := range results {
		resultMap, ok := val.(map[string]any)
		if !ok {
			continue
		}
		factors[key] = scoreResult(key, resultMap)
	}
	return factors
}

func (a *Agent) generateSummary(results map[string]any) string {
	if len(results) == 0 {
		return "No results available."
	}

	parts := make([]string, 0)
	for key, val := range results {
		resultMap, ok := val.(map[string]any)
		if !ok {
			continue
		}

		reputation, _ := resultMap["reputation"].(string)
		if reputation == "malicious" {
			parts = append(parts, fmt.Sprintf("[HIGH] %s: malicious", key))
		} else if reputation == "suspicious" {
			parts = append(parts, fmt.Sprintf("[MED] %s: suspicious", key))
		}

		if cv := getFloat(resultMap["count"]); cv > 0 {
			parts = append(parts, fmt.Sprintf("[YARA] %s: %d rule(s) matched", key, int(cv)))
			switch m := resultMap["matches"].(type) {
			case []any:
				for _, v := range m {
					parts = append(parts, fmt.Sprintf("[DETECT] %s: %v", key, v))
				}
			case []string:
				for _, v := range m {
					parts = append(parts, fmt.Sprintf("[DETECT] %s: %s", key, v))
				}
			}
		}

		if suspiciousList, ok := resultMap["suspicious"].([]any); ok && len(suspiciousList) > 0 {
			for _, s := range suspiciousList {
				parts = append(parts, fmt.Sprintf("[WARN] %s: %v", key, s))
			}
		}
	}

	if len(parts) == 0 {
		return "Investigation completed. No significant findings."
	}

	seen := make(map[string]bool)
	unique := make([]string, 0, len(parts))
	for _, p := range parts {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}

	return strings.Join(unique, "\n")
}

func (a *Agent) extractFindings(results map[string]any) []map[string]any {
	var findings []map[string]any
	for key, val := range results {
		resultMap, ok := val.(map[string]any)
		if !ok {
			continue
		}

		reputation, _ := resultMap["reputation"].(string)
		if reputation == "malicious" {
			findings = append(findings, map[string]any{
				"source": key,
				"type":   "malicious_indicator",
				"detail": reputation,
			})
		}

		if getFloat(resultMap["count"]) > 0 {
			switch m := resultMap["matches"].(type) {
			case []any:
				for _, v := range m {
					findings = append(findings, map[string]any{"source": key, "type": "yara_match", "detail": fmt.Sprintf("%v", v)})
				}
			case []string:
				for _, v := range m {
					findings = append(findings, map[string]any{"source": key, "type": "yara_match", "detail": v})
				}
			}
		}

		if suspiciousList, ok := resultMap["suspicious"].([]any); ok {
			for _, s := range suspiciousList {
				findings = append(findings, map[string]any{
					"source": key,
					"type":   "suspicious",
					"detail": fmt.Sprintf("%v", s),
				})
			}
		}
	}
	return findings
}

func (a *Agent) extractIndicators(results map[string]any) []string {
	var indicators []string
	for key, val := range results {
		resultMap, ok := val.(map[string]any)
		if !ok {
			continue
		}

		for _, field := range []string{"md5", "sha1", "sha256", "hash", "ip", "domain", "url", "indicator"} {
			if v, ok := resultMap[field].(string); ok && v != "" && v != "unknown" {
				indicators = append(indicators, fmt.Sprintf("%s (%s)", v, key))
			}
		}
	}
	return indicators
}

func formatMarkdownReport(intent, investigationID string, confidence float64, summary string, findings []map[string]any, indicators []string, results map[string]any) string {
	var b strings.Builder

	b.WriteString("# Investigation Report\n\n")
	b.WriteString(fmt.Sprintf("**Intent:** %s\n", intent))
	b.WriteString(fmt.Sprintf("**ID:** `%s`\n", investigationID))
	b.WriteString(fmt.Sprintf("**Confidence:** %.0f%%\n\n", confidence*100))

	b.WriteString("## Summary\n")
	if summary != "" {
		b.WriteString(summary + "\n")
	} else {
		b.WriteString("Investigation completed.\n")
	}
	b.WriteString("\n")

	b.WriteString("## Findings\n")
	if len(findings) > 0 {
		for _, f := range findings {
			b.WriteString(fmt.Sprintf("- **%s** [%s]: %v\n", f["type"], f["source"], f["detail"]))
		}
	} else {
		b.WriteString("No significant findings.\n")
	}
	b.WriteString("\n")

	b.WriteString("## Indicators\n")
	if len(indicators) > 0 {
		for _, i := range indicators {
			b.WriteString(fmt.Sprintf("- `%s`\n", i))
		}
	} else {
		b.WriteString("No indicators extracted.\n")
	}
	b.WriteString("\n")

	b.WriteString("## Agent Results\n")
	for key, val := range results {
		b.WriteString(fmt.Sprintf("### %s\n", key))
		resultMap, ok := val.(map[string]any)
		if !ok {
			b.WriteString(fmt.Sprintf("  %v\n", val))
			continue
		}

		reputation, _ := resultMap["reputation"].(string)
		if reputation != "" {
			b.WriteString(fmt.Sprintf("- **Reputation:** %s\n", reputation))
		}

		if desc, ok := resultMap["description"].(string); ok && desc != "" {
			b.WriteString(fmt.Sprintf("- **Description:** %s\n", desc))
		}

		if cv := getFloat(resultMap["count"]); cv > 0 {
			b.WriteString(fmt.Sprintf("- **YARA matches:** %d\n", int(cv)))
		}

		if suspiciousList, ok := resultMap["suspicious"].([]any); ok && len(suspiciousList) > 0 {
			b.WriteString(fmt.Sprintf("- **Suspicious indicators:** %d\n", len(suspiciousList)))
		}

		if mitigations, ok := resultMap["mitigations"].([]any); ok && len(mitigations) > 0 {
			b.WriteString("- **Mitigations:**\n")
			for _, m := range mitigations {
				b.WriteString(fmt.Sprintf("  - %s\n", m))
			}
		}

		if detection, ok := resultMap["detection"].([]any); ok && len(detection) > 0 {
			b.WriteString("- **Detection guidance:**\n")
			for _, d := range detection {
				b.WriteString(fmt.Sprintf("  - %s\n", d))
			}
		}

		errorStr, _ := resultMap["error"].(string)
		if errorStr != "" {
			b.WriteString(fmt.Sprintf("- **Error:** %s\n", errorStr))
		}
	}
	b.WriteString("\n")

	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("*Generated by Trace v0.1.0-dev*"))

	return b.String()
}

func pickPlaybook(intent string, engine *playbook.Engine, input agent.Input) string {
	if engine == nil {
		return "hash-lookup"
	}
	if v, ok := input["action"]; ok && v == "plan_investigation" {
		return ""
	}

	if technique, _ := input["technique"].(string); technique != "" {
		if pb := engine.Get("mitre-lookup"); pb != nil {
			return "mitre-lookup"
		}
	}
	if cveID, _ := input["cve_id"].(string); cveID != "" {
		if pb := engine.Get("cve-lookup"); pb != nil {
			return "cve-lookup"
		}
	}
	if hash, _ := input["hash"].(string); hash != "" {
		if pb := engine.Get("hash-lookup"); pb != nil {
			return "hash-lookup"
		}
	}
	if ip, _ := input["ip"].(string); ip != "" {
		if pb := engine.Get("ip-reputation"); pb != nil {
			return "ip-reputation"
		}
	}
	if url, _ := input["url"].(string); url != "" {
		if pb := engine.Get("url-scan"); pb != nil {
			return "url-scan"
		}
	}

	return classifyIntent(intent, engine)
}

func classifyIntent(intent string, engine *playbook.Engine) string {
	intentLower := strings.ToLower(intent)

	for _, pb := range engine.List() {
		for _, trigger := range pb.Triggers {
			if strings.Contains(intentLower, trigger) {
				return pb.Name
			}
		}
	}

	if strings.Contains(intentLower, "hash") || strings.Contains(intentLower, "sha256") || strings.Contains(intentLower, "md5") {
		return "hash-lookup"
	}
	if strings.Contains(intentLower, "file") || strings.Contains(intentLower, "malware") || strings.Contains(intentLower, "exe") {
		return "file-analysis"
	}
	if strings.Contains(intentLower, "ip") || strings.Contains(intentLower, "address") {
		return "ip-reputation"
	}
	if strings.Contains(intentLower, "url") || strings.Contains(intentLower, "link") {
		return "url-scan"
	}

	if list := engine.List(); len(list) > 0 {
		return list[0].Name
	}

	return "hash-lookup"
}

func extractParams(intent string, pb *playbook.Playbook) map[string]any {
	params := make(map[string]any)

	switch pb.Name {
	case "hash-lookup":
		if hash := extractHash(intent); hash != "" {
			params["hash"] = hash
		}
	case "file-analysis":
		if hash := extractHash(intent); hash != "" {
			params["hash"] = hash
		}
	case "ip-reputation":
		if ip := extractIP(intent); ip != "" {
			params["ip"] = ip
		}
	case "mitre-lookup":
		if technique := extractTechnique(intent); technique != "" {
			params["technique"] = technique
		}
	case "cve-lookup":
		if cve := extractCVE(intent); cve != "" {
			params["cve_id"] = cve
		}
	}

	return params
}

func extractHash(s string) string {
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, ".,;:\"'")
		if len(f) == 64 {
			return f
		}
		if len(f) == 40 {
			return f
		}
		if len(f) == 32 {
			return f
		}
	}
	return ""
}

func extractIP(s string) string {
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, ".,;:\"'")
		parts := strings.Split(f, ".")
		if len(parts) == 4 {
			return f
		}
	}
	return ""
}

func extractTechnique(s string) string {
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, ".,;:\"'")
		if strings.HasPrefix(strings.ToUpper(f), "T") && len(f) >= 4 {
			return strings.ToUpper(f)
		}
	}
	return ""
}

func extractCVE(s string) string {
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, ".,;:\"'")
		if strings.HasPrefix(strings.ToUpper(f), "CVE-") {
			return strings.ToUpper(f)
		}
	}
	return ""
}

func sortResults(results map[string]any) []string {
	keys := make([]string, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}


