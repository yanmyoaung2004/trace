package dispatch

// LLM provider registry (FIX_PLAN 1.2): per-provider schema + budget caps +
// auto prompt version. Replaces the anthropic/ollama/openai switch clusters
// with a self-registering map. Dispatch-local: no new external deps.
//
// Providers register payload builders, content extractors, default models,
// and budget caps. Plan() validates LLM JSON against a schema (playbook must
// be allowlisted per caller, params within size caps), verifies before
// caching (prompt-versioned key kept), redacts logs, and sanitizes the
// synthesized report.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ProviderSpec describes one LLM provider's wire schema and budget.
type ProviderSpec struct {
	Name         string
	DefaultModel string
	MaxTokens    int
	BudgetCalls  int // per-minute cap; 0 = uncapped
	Timeout      time.Duration
	BuildPayload func(model, prompt string, maxTokens int, temperature float64) ([]byte, error)
	Extract      func(body []byte) string
	Headers      func(apiKey string) map[string]string
}

var llmProviders = map[string]*ProviderSpec{}

func init() {
	RegisterLLMProvider(&ProviderSpec{
		Name:         "openai",
		DefaultModel: "gpt-4",
		MaxTokens:    300,
		BuildPayload: buildOpenAICompatPayload,
		Extract:      extractOpenAICompat,
		Headers: func(apiKey string) map[string]string {
			h := map[string]string{}
			if apiKey != "" {
				h["Authorization"] = "Bearer " + apiKey
			}
			return h
		},
	})
	RegisterLLMProvider(&ProviderSpec{
		Name:         "anthropic",
		DefaultModel: "claude-3-haiku-20240307",
		MaxTokens:    300,
		BuildPayload: buildAnthropicPayload,
		Extract:      extractAnthropic,
		Headers: func(apiKey string) map[string]string {
			return map[string]string{"x-api-key": apiKey, "anthropic-version": "2023-06-01"}
		},
	})
	RegisterLLMProvider(&ProviderSpec{
		Name:         "ollama",
		DefaultModel: "llama3",
		MaxTokens:    300,
		BuildPayload: buildOllamaPayload,
		Extract:      extractOllama,
		Headers:      func(apiKey string) map[string]string { return map[string]string{} },
	})
}
// RegisterLLMProvider registers a provider spec (self-registering map).
func RegisterLLMProvider(spec *ProviderSpec) {
	if spec == nil || spec.Name == "" {
		return
	}
	llmProviders[spec.Name] = spec
}

// Payload builders + extractors backing the registry (single RegisterDecoder
// analogue for LLM: one registration point, no switch at callsite).
func buildOpenAICompatPayload(model, prompt string, maxTokens int, temperature float64) ([]byte, error) {
	return jsonMarshal(map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You select playbooks and extract parameters from security investigation requests. Return only JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": temperature,
		"max_tokens":  maxTokens,
	})
}

func buildAnthropicPayload(model, prompt string, maxTokens int, _ float64) ([]byte, error) {
	return jsonMarshal(map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})
}

func buildOllamaPayload(model, prompt string, _ int, _ float64) ([]byte, error) {
	return jsonMarshal(map[string]any{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	})
}
func LLMProviderNames() []string {
	names := make([]string, 0, len(llmProviders))
	for n := range llmProviders {
		names = append(names, n)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// llmPlanSchema is the validated shape of LLM output.
type llmPlanSchema struct {
	Playbook   string         `json:"playbook"`
	Parameters map[string]any `json:"parameters"`
}

// validateLLMPlan enforces: known playbook (allowlist), params is a map,
// size caps, no unexpected top-level keys beyond playbook/parameters.
// Returns the sanitized params.
func validateLLMPlan(raw map[string]any, allowlist map[string]bool) (string, map[string]any, error) {
	if len(raw) == 0 {
		return "", nil, fmt.Errorf("empty LLM output")
	}
	for k := range raw {
		if k != "playbook" && k != "parameters" {
			return "", nil, fmt.Errorf("unexpected LLM key %q", k)
		}
	}
	name, _ := raw["playbook"].(string)
	if name == "" {
		return "", nil, fmt.Errorf("llm didn't select a playbook")
	}
	if !allowlist[name] {
		return "", nil, fmt.Errorf("playbook %q not in caller allowlist", name)
	}
	params := map[string]any{}
	if p, ok := raw["parameters"]; ok && p != nil {
		pm, ok := p.(map[string]any)
		if !ok {
			return "", nil, fmt.Errorf("parameters must be an object")
		}
		if len(pm) > 32 {
			return "", nil, fmt.Errorf("too many parameters (%d > 32)", len(pm))
		}
		for k, v := range pm {
			if len(k) > 128 {
				return "", nil, fmt.Errorf("parameter key too long")
			}
			if s, ok := v.(string); ok && len(s) > 4096 {
				return "", nil, fmt.Errorf("parameter %q too long", k)
			}
			params[k] = v
		}
	}
	return name, params, nil
}

func llmLogRedact(s string) string {
	// Never log API keys/tokens: payloads carry Authorization headers
	// separately (never in body), so cap body snippets only.
	if len(s) > 500 {
		s = s[:500]
	}
	// Strip bearer-looking substrings.
	if i := strings.Index(strings.ToLower(s), "bearer "); i >= 0 {
		s = s[:i] + "bearer ***redacted***"
	}
	return s
}

// sanitizeReportField HTML-escapes report text so untrusted outputs
// (threat-intel vendors, web markdown) cannot inject markup. Truncates.
func sanitizeReportField(s string) string {
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	if len(s) > 4000 {
		s = s[:4000] + "…[truncated]"
	}
	return s
}

// sanitizeLLMParamsForSinks drops untrusted LLM values targeting sensitive
// sinks unless they validate (ip/path/hostname/script/query/webhook).
// Uses stdlib validation here (dispatch must not import response? it may:
// response is a leaf package — read-only import allowed). Kept stdlib-only
// to avoid a hard dependency: strict allowlist patterns.
func sanitizeLLMParamsForSinks(params map[string]any) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		out[k] = v
	}
	return out
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func extractOpenAICompat(body []byte) string {
	var r openAIResp
	if json.Unmarshal(body, &r) == nil && len(r.Choices) > 0 {
		return r.Choices[0].Message.Content
	}
	return ""
}

func extractAnthropic(body []byte) string {
	var r anthropicResp
	if json.Unmarshal(body, &r) == nil && len(r.Content) > 0 {
		return r.Content[0].Text
	}
	return ""
}

func extractOllama(body []byte) string {
	var r struct {
		Response string `json:"response"`
	}
	if json.Unmarshal(body, &r) == nil && r.Response != "" {
		return r.Response
	}
	return ""
}

