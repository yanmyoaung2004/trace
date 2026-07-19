package siem

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed rules/*.yaml
var embeddedRuleFS embed.FS

type RuleSet struct {
	Name     string
	Rules    []CompiledRule
}

type CompiledRule struct {
	RuleID      string
	Description string
	Severity    int
	MITRE       string
	Actions     []RuleAction

	condition string
	field     string
	operator  string
	value     string
	re        *regexp.Regexp
	windowDur time.Duration
	suppress  time.Duration
	threshold int
}

type RuleAction struct {
	Playbook string
	Params   map[string]any
}

type RuleEngine struct {
	rules     []CompiledRule
	mu        sync.RWMutex

	correlation   map[string][]time.Time
	correlationMu sync.Mutex

	suppression   map[string]time.Time
	suppressionMu sync.Mutex
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		correlation: make(map[string][]time.Time),
		suppression: make(map[string]time.Time),
	}
}

type YAMLRule struct {
	RuleID      string            `yaml:"rule_id"`
	Description string            `yaml:"description"`
	Severity    int               `yaml:"severity"`
	MITRE       string            `yaml:"mitre,omitempty"`
	Condition   string            `yaml:"condition"`
	WindowDur   string            `yaml:"window,omitempty"`
	Threshold   int               `yaml:"threshold,omitempty"`
	Suppress    string            `yaml:"suppress,omitempty"`
	Playbook    string            `yaml:"playbook,omitempty"`
	Params      map[string]string `yaml:"params,omitempty"`
}

type YAMLRuleFile struct {
	Rules []YAMLRule `yaml:"rules"`
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err == nil {
		return d
	}
	return 0
}

func (re *RuleEngine) LoadYAML(data []byte) error {
	var file YAMLRuleFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	re.mu.Lock()
	defer re.mu.Unlock()
	for _, yr := range file.Rules {
		cr := CompiledRule{
			RuleID:      yr.RuleID,
			Description: yr.Description,
			Severity:    yr.Severity,
			MITRE:       yr.MITRE,
			condition:   yr.Condition,
			windowDur:   parseDuration(yr.WindowDur),
			threshold:   yr.Threshold,
			suppress:    parseDuration(yr.Suppress),
		}
		if yr.Playbook != "" {
			params := make(map[string]any)
			for k, v := range yr.Params {
				params[k] = v
			}
			cr.Actions = []RuleAction{{Playbook: yr.Playbook, Params: params}}
		}
		re.rules = append(re.rules, cr)
	}
	return nil
}

func (re *RuleEngine) LoadBuiltinYAML() error {
	entries, err := embeddedRuleFS.ReadDir("rules")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := embeddedRuleFS.ReadFile("rules/" + e.Name())
		if err != nil {
			return fmt.Errorf("read builtin %s: %w", e.Name(), err)
		}
		if err := re.LoadYAML(data); err != nil {
			return fmt.Errorf("load builtin %s: %w", e.Name(), err)
		}
	}
	return nil
}

func (re *RuleEngine) LoadYAMLDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		if err := re.LoadYAML(data); err != nil {
			return fmt.Errorf("load %s: %w", e.Name(), err)
		}
	}
	return nil
}

func (re *RuleEngine) LoadDefault() {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.rules = loadWazuhRules()
	re.rules = append(re.rules, builtinRules()...)

	fmt.Printf("[siem] loaded %d external + %d built-in rules\n", len(loadWazuhRules()), len(builtinRules()))
}

func builtinRules() []CompiledRule {
	return []CompiledRule{
		{RuleID: "MULTIPLE_FAILED_LOGINS", Description: "Multiple failed login attempts from same source",
			Severity: 4, MITRE: "T1110.003", condition: "tag:auth_failure", threshold: 5, windowDur: 60 * time.Second,
			Actions: []RuleAction{{Playbook: "ip-reputation", Params: map[string]any{"ip": "${source_ip}"}}}},
		{RuleID: "FAILED_LOGIN_BRUTE", Description: "Single source brute-forcing login",
			Severity: 5, MITRE: "T1110", condition: "tag:auth_failure", threshold: 20, windowDur: 60 * time.Second},
		{RuleID: "HTTP_5XX_ERROR", Description: "Server error response",
			Severity: 3, condition: "tag:http_error", threshold: 1},
		{RuleID: "HTTP_4XX_BURST", Description: "Multiple client errors from same source",
			Severity: 2, condition: "tag:http_client_error", threshold: 10, windowDur: 60 * time.Second,
			Actions: []RuleAction{{Playbook: "ip-reputation", Params: map[string]any{"ip": "${client_ip}"}}}},
		{RuleID: "SUSPICIOUS_PROCESS", Description: "Suspicious process execution detected",
			Severity: 4, MITRE: "T1059", condition: "tag:process",
			Actions: []RuleAction{{Playbook: "file-analysis", Params: map[string]any{"path": "${process_path}"}}}},
		{RuleID: "HIGH_SEVERITY_ERROR", Description: "High severity error in system logs",
			Severity: 3, condition: "tag:error", threshold: 1},
		{RuleID: "WINDOWS_EVENT_4625_BURST", Description: "Multiple Windows failed logon events",
			Severity: 4, MITRE: "T1110.003", condition: "tag:auth_failure", threshold: 5, windowDur: 60 * time.Second},
		{RuleID: "BRUTE_FORCE_FALLBACK", Description: "Multiple auth failures from same source (any service)",
			Severity: 3, MITRE: "T1110", condition: "field:message ~= (?i)failed", threshold: 10, windowDur: 120 * time.Second},
		{RuleID: "WIN_POWERSHELL_4104", Description: "PowerShell script block logging (Event 4104)",
			Severity: 3, MITRE: "T1059.001", condition: "tag:powershell", threshold: 1,
			Actions: []RuleAction{{Playbook: "log-analysis", Params: map[string]any{"event_id": "4104"}}}},
		{RuleID: "WIN_SCHEDULED_TASK_4698", Description: "Scheduled task created (Event 4698) — potential persistence",
			Severity: 4, MITRE: "T1053.005", condition: "tag:persistence", threshold: 1,
			Actions: []RuleAction{{Playbook: "file-analysis", Params: map[string]any{"path": "${process_path}"}}}},
		{RuleID: "WIN_SERVICE_INSTALL_7045", Description: "New service installed (Event 7045)",
			Severity: 4, MITRE: "T1543.003", condition: "tag:service_install", threshold: 1},
		{RuleID: "WIN_DEFENDER_1116", Description: "Windows Defender detected malware (Event 1116)",
			Severity: 5, MITRE: "T1204", condition: "tag:malware_detection", threshold: 1,
			Actions: []RuleAction{{Playbook: "file-analysis", Params: map[string]any{"path": "${file_path}"}}}},
		{RuleID: "WIN_PROCESS_4688_CREATION", Description: "Process creation with command line (Event 4688)",
			Severity: 2, MITRE: "T1059", condition: "tag:process_creation", threshold: 1},
		{RuleID: "WIN_REGISTRY_PERSISTENCE", Description: "Registry persistence modification (Event 4657)",
			Severity: 3, MITRE: "T1547.001", condition: "tag:registry_change", threshold: 1},
		{RuleID: "WIN_RDP_LOGIN_4625", Description: "RDP failed login (Event 4625, LogonType 10)",
			Severity: 3, MITRE: "T1021.001", condition: "field:logontype == 10", threshold: 1},
		{RuleID: "WIN_ACCOUNT_LOCKOUT_4740", Description: "User account locked out (Event 4740)",
			Severity: 3, MITRE: "T1110", condition: "tag:account_lockout", threshold: 1},
	}
}

func (re *RuleEngine) LoadRule(r CompiledRule) {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.rules = append(re.rules, r)
}

func (re *RuleEngine) Evaluate(event *Event) []*Alert {
	re.mu.RLock()
	rules := make([]CompiledRule, len(re.rules))
	copy(rules, re.rules)
	re.mu.RUnlock()

	var alerts []*Alert
	now := time.Now()

	for _, rule := range rules {
		if !re.matchesCondition(rule, event) {
			continue
		}

		suppressKey := rule.RuleID
		if rule.suppress > 0 {
			re.suppressionMu.Lock()
			if last, ok := re.suppression[suppressKey]; ok && now.Sub(last) < rule.suppress {
				re.suppressionMu.Unlock()
				continue
			}
			re.suppression[suppressKey] = now
			re.suppressionMu.Unlock()
		}

		if rule.windowDur > 0 && rule.threshold > 1 {
			corrKey := rule.RuleID + ":" + correlationKey(event, rule)
			re.correlationMu.Lock()
			re.correlation[corrKey] = append(re.correlation[corrKey], now)
			events := re.correlation[corrKey]

			var active []time.Time
			windowStart := now.Add(-rule.windowDur)
			for _, t := range events {
				if t.After(windowStart) {
					active = append(active, t)
				}
			}
			re.correlation[corrKey] = active
			re.correlationMu.Unlock()

			if len(active) < rule.threshold {
				continue
			}
		}

		alert := &Alert{
			ID:          fmt.Sprintf("%s-%d", rule.RuleID, now.UnixNano()),
			Title:       rule.Description,
			Severity:    rule.Severity,
			MITRE:       rule.MITRE,
			Source:      "siem",
			Event:       event,
			RuleID:      rule.RuleID,
			Actions:     rule.Actions,
			CreatedAt:   now,
		}
		alerts = append(alerts, alert)
	}

	return alerts
}

func (re *RuleEngine) matchesCondition(rule CompiledRule, event *Event) bool {
	if rule.condition == "" {
		return false
	}

	cond := rule.condition

	if strings.HasPrefix(cond, "tag:") {
		tag := strings.TrimPrefix(cond, "tag:")
		for _, t := range event.Tags {
			if t == tag || strings.Contains(t, tag) {
				return true
			}
		}
		return false
	}

	if strings.HasPrefix(cond, "field:") {
		fieldExpr := strings.TrimPrefix(cond, "field:")
		return evaluateFieldExpr(fieldExpr, event)
	}

	if strings.HasPrefix(cond, "severity>=") {
		minSev, _ := strconv.Atoi(cond[len("severity>="):])
		return event.Severity >= minSev
	}

	return false
}

func evaluateFieldExpr(expr string, event *Event) bool {
	parts := strings.SplitN(expr, " ", 3)
	if len(parts) < 3 {
		return false
	}

	field := parts[0]
	operator := parts[1]
	val := parts[2]

	fieldVal := getField(event.Fields, field)

	switch operator {
	case "==":
		return fmt.Sprintf("%v", fieldVal) == val
	case "!=":
		return fmt.Sprintf("%v", fieldVal) != val
	case "~=":
		pattern := strings.Trim(val, "\"")
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", fieldVal))
	case ">":
		fv, _ := strconv.ParseFloat(fmt.Sprintf("%v", fieldVal), 64)
		tv, _ := strconv.ParseFloat(val, 64)
		return fv > tv
	case "<":
		fv, _ := strconv.ParseFloat(fmt.Sprintf("%v", fieldVal), 64)
		tv, _ := strconv.ParseFloat(val, 64)
		return fv < tv
	case "in":
		return cidrMatch(fmt.Sprintf("%v", fieldVal), val)
	}

	return false
}

func getField(fields map[string]any, path string) any {
	parts := strings.Split(path, ".")
	current := fields
	for i, part := range parts {
		val, ok := current[part]
		if !ok {
			return nil
		}
		if i == len(parts)-1 {
			return val
		}
		if m, ok := val.(map[string]any); ok {
			current = m
		} else {
			return nil
		}
	}
	return nil
}

func correlationKey(event *Event, rule CompiledRule) string {
	switch rule.RuleID {
	case "MULTIPLE_FAILED_LOGINS", "HTTP_4XX_BURST":
		if ip, ok := event.Fields["client_ip"].(string); ok {
			return ip
		}
		return fmt.Sprintf("%v", event.Fields["hostname"])
	default:
		return ""
	}
}

func cidrMatch(ip, cidr string) bool {
	return strings.HasPrefix(ip, strings.Split(cidr, "/")[0])
}

func InterpolateParams(params map[string]any, event *Event) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		str, ok := v.(string)
		if !ok {
			out[k] = v
			continue
		}
		for fk, fv := range event.Fields {
			placeholder := "${" + fk + "}"
			str = strings.ReplaceAll(str, placeholder, fmt.Sprintf("%v", fv))
		}
		out[k] = str
	}
	return out
}
