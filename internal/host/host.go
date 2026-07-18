package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/innoigniter/edge/internal/agent"
	"github.com/innoigniter/edge/internal/playbook"
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

func (a *Agent) WithPlanner(provider, url, apiKey string) *Agent {
	a.planner = NewLLMPlanner(provider, url, apiKey)
	return a
}

func (a *Agent) Name() string { return "host" }

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

func (a *Agent) planInvestigation(_ context.Context, input agent.Input) (agent.Output, error) {
	intent, _ := input["intent"].(string)
	if intent == "" {
		return nil, fmt.Errorf("intent is required")
	}

	playbookName := pickPlaybook(intent, a.playbooks, input)
	if playbookName == "" {
		playbookName = "hash-lookup"
	}

	pb := a.playbooks.Get(playbookName)
	if pb == nil {
		return agent.Output{"playbook": "hash-lookup", "parameters": input}, nil
	}

	params := extractParams(intent, pb)

	return agent.Output{
		"playbook":   pb.Name,
		"parameters": params,
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

type LLMPlanner struct {
	Provider string
	URL      string
	APIKey   string
	client   *http.Client
}

func NewLLMPlanner(provider, url, apiKey string) *LLMPlanner {
	return &LLMPlanner{
		Provider: provider,
		URL:      url,
		APIKey:   apiKey,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (lp *LLMPlanner) Plan(ctx context.Context, intent string, availablePlaybooks []string) (string, map[string]any, error) {
	if lp.URL == "" || lp.APIKey == "" {
		return "", nil, fmt.Errorf("LLM planner not configured")
	}

	prompt := fmt.Sprintf(`You are a cybersecurity investigation planner. Given the user's intent, select the best playbook from: %s.
Return JSON: {"playbook": "name", "parameters": {"key": "value"}}
Intent: %s`, strings.Join(availablePlaybooks, ", "), intent)

	body := map[string]any{
		"model": "gpt-4",
		"messages": []map[string]string{
			{"role": "system", "content": "You select playbooks and extract parameters from security investigation requests."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.1,
		"max_tokens":  200,
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", lp.URL, bytes.NewReader(payload))
	if err != nil {
		return "", nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+lp.APIKey)

	resp, err := lp.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("llm request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result struct {
		Playbook   string         `json:"playbook"`
		Parameters map[string]any `json:"parameters"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		_ = err
	}

	if result.Playbook == "" {
		return "", nil, fmt.Errorf("llm returned no playbook")
	}

	return result.Playbook, result.Parameters, nil
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
	b.WriteString(fmt.Sprintf("*Generated by InnoIgniterAI v0.1.0-dev*"))

	return b.String()
}

func pickPlaybook(intent string, engine *playbook.Engine, input agent.Input) string {
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


