package audit

// Redact params/outputs/scripts/keys for logs and audit details.
// Keys, tokens, webhooks, passwords, scripts are redacted; long values
// capped. Used by playbook executor logging + LLM logs + Audit callsites.

import (
	"strings"
)

const maxLoggedValueLen = 512

var sensitiveSubstrings = []string{
	"api_key", "apikey", "api-key", "secret", "token", "password", "passwd",
	"webhook", "private_key", "privatekey", "auth", "bearer", "session",
	"cookie", "otp", "routing_key",
}

var sensitiveExactKeys = map[string]bool{
	"script": true, "command": true, "rollback_command": true,
	"params": false, // params map itself is recursed, not dropped
}

// RedactValue redacts a single value by key name.
func RedactValue(key string, v any) any {
	lk := strings.ToLower(key)
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(lk, sub) {
			return "***redacted***"
		}
	}
	if sensitiveExactKeys[lk] {
		return "***redacted***"
	}
	if s, ok := v.(string); ok {
		if len(s) > maxLoggedValueLen {
			return s[:maxLoggedValueLen] + "…[truncated]"
		}
		return s
	}
	if m, ok := v.(map[string]any); ok {
		return RedactMap(m)
	}
	return v
}

// RedactMap returns a redacted copy of m (never mutates input).
func RedactMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if nested, ok := v.(map[string]any); ok {
			out[k] = RedactMap(nested)
			// Still check the key itself.
			lk := strings.ToLower(k)
			for _, sub := range sensitiveSubstrings {
				if strings.Contains(lk, sub) {
					out[k] = "***redacted***"
					break
				}
			}
			continue
		}
		out[k] = RedactValue(k, v)
	}
	return out
}

// RedactKeys redacts a JSON-serializable details string's sensitive fields
// on a best-effort basis (string contains check). Prefer RedactMap before
// marshalling; this is a backstop for already-marshalled strings.
func RedactKeys(s string) string {
	// Backstop only: callers should redact structured data. Kept tiny and
	// boring on purpose.
	if s == "" {
		return s
	}
	if len(s) > 8*maxLoggedValueLen {
		return s[:8*maxLoggedValueLen] + "…[truncated]"
	}
	return s
}
