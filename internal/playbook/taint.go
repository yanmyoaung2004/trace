package playbook

// Taint isolation: untrusted step outputs (threat-intel vendors, web
// markdown, SIEM _raw, logs, file bytes) cannot flow into
// ip/path/hostname/script/query/webhook sinks or the report without
// sanitization.
//
// Provenance, not envelopes: Scope.Tainted marks result keys whose values
// came from a step execution. Before executing response/edr steps, params
// whose template references ${outputs...}/${result...} are sink-validated
// with the shared response validators (read-only import). Trusted input
// (${input...}) flows through untouched.

import (
	"fmt"
	"html"
	"regexp"
	"strings"

	"github.com/yanmyoaung2004/trace/internal/response"
)

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$`)

// sinkKeys are param names treated as trust sinks.
var sinkKeys = map[string]bool{
	"ip": true, "path": true, "hostname": true, "host": true,
	"script": true, "query": true, "webhook": true, "url": true,
}

// templateRefsUntrusted reports whether a param template pulls from step
// outputs (vs. direct operator input).
func templateRefsUntrusted(template any) bool {
	s, ok := template.(string)
	if !ok {
		return false
	}
	return strings.Contains(s, "${outputs.") || strings.Contains(s, "${result.")
}

// SanitizeSinkParams validates/sanitizes interpolated params for
// response/edr steps. Untrusted values into sinks are validated strictly
// (deny on failure); query/webhook/url are sanitized strings. Templates are
// the pre-interpolation step params (for provenance).
func SanitizeSinkParams(agent string, templates, params map[string]any) (map[string]any, error) {
	if agent != "response" && agent != "edr" {
		return params, nil
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		out[k] = v
		tmpl, hasTmpl := templates[k]
		if !hasTmpl || !templateRefsUntrusted(tmpl) {
			continue
		}
		if !sinkKeys[strings.ToLower(k)] {
			continue
		}
		s, _ := v.(string)
		switch strings.ToLower(k) {
		case "ip":
			if _, err := response.ValidateIP(s); err != nil {
				return nil, fmt.Errorf("tainted param ip rejected: %w", err)
			}
		case "path":
			if err := response.ValidateFilePath(s); err != nil {
				return nil, fmt.Errorf("tainted param path rejected: %w", err)
			}
		case "hostname", "host":
			if !hostnameRe.MatchString(s) {
				return nil, fmt.Errorf("tainted param %s rejected: bad hostname %q", k, s)
			}
		case "script":
			// run_script is deny-by-default; untrusted scripts never flow.
			if err := response.CheckRunScriptGate(map[string]any{"script": s}); err != nil {
				return nil, fmt.Errorf("tainted script rejected: %w", err)
			}
		case "query", "webhook", "url":
			out[k] = SanitizeString(s)
		}
	}
	// Client-side chains must be expanded server-side, never executed.
	if err := response.CheckChainRejected(params); err != nil {
		return nil, err
	}
	return out, nil
}

// SanitizeForReport renders a value safe for markdown report inclusion:
// HTML-escapes strings, truncates long values.
func SanitizeForReport(v any) string {
	s := fmt.Sprintf("%v", v)
	return SanitizeString(s)
}

// SanitizeString HTML-escapes and trims s for sink-adjacent use.
func SanitizeString(s string) string {
	s = html.EscapeString(strings.TrimSpace(s))
	if len(s) > 2000 {
		s = s[:2000] + "…[truncated]"
	}
	return s
}
