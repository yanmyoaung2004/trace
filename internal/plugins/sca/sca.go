package sca

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
	"gopkg.in/yaml.v3"
)

type SCAPolicy struct {
	Policy struct {
		ID          string   `yaml:"id"`
		Name        string   `yaml:"name"`
		Description string   `yaml:"description"`
		References  []string `yaml:"references"`
	} `yaml:"policy"`
	Requirements struct {
		Title       string   `yaml:"title"`
		Description string   `yaml:"description"`
		Condition   string   `yaml:"condition"`
		Rules       []string `yaml:"rules"`
	} `yaml:"requirements"`
	Variables map[string]string `yaml:"variables"`
	Checks    []SCACheck        `yaml:"checks"`
}

type SCACheck struct {
	ID          int                    `yaml:"id"`
	Title       string                 `yaml:"title"`
	Description string                 `yaml:"description"`
	Rationale   string                 `yaml:"rationale"`
	Remediation string                 `yaml:"remediation"`
	Condition   string                 `yaml:"condition"`
	Rules       []string               `yaml:"rules"`
	Compliance  []map[string][]string  `yaml:"compliance,flow"`
}

func (c *SCACheck) ComplianceMap() map[string][]string {
	out := make(map[string][]string)
	for _, m := range c.Compliance {
		for k, v := range m {
			out[k] = append(out[k], v...)
		}
	}
	return out
}

type Agent struct{}

func New() *Agent { return &Agent{} }

func (a *Agent) Name() string { return "sca" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "run_policy", Inputs: []string{"policy_data"}, Outputs: []string{"results", "pass", "fail", "total"}},
		{Action: "scan_system", Inputs: []string{}, Outputs: []string{"policy", "score", "results"}},
		{Action: "list_policies", Inputs: []string{}, Outputs: []string{"policies"}},
	}
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "run_policy":
		return a.runPolicy(ctx, input)
	case "scan_system":
		return a.scanSystem(ctx)
	case "list_policies":
		return a.listPolicies()
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) listPolicies() (agent.Output, error) {
	var list []map[string]string
	for _, p := range ListPolicies() {
		list = append(list, map[string]string{"id": p.ID, "name": p.Name})
	}
	return agent.Output{"policies": list, "count": len(list)}, nil
}

func (a *Agent) scanSystem(ctx context.Context) (agent.Output, error) {
	policy := DetectOSPolicy()
	if policy == nil {
		return agent.Output{"error": "no matching policy for this OS"}, nil
	}
	return a.runPolicy(ctx, agent.Input{"policy_data": policy.Data, "policy_name": policy.ID})
}

type checkResult struct {
	ID          int                 `json:"id"`
	Title       string              `json:"title"`
	Status      string              `json:"status"`
	Rationale   string              `json:"rationale,omitempty"`
	Remediation string              `json:"remediation,omitempty"`
	Errors      []string            `json:"errors,omitempty"`
	Compliance  map[string][]string `json:"compliance,omitempty"`
}

func (a *Agent) runPolicy(ctx context.Context, input agent.Input) (agent.Output, error) {
	policyData, _ := input["policy_data"].(string)
	if policyData == "" {
		file, _ := input["file"].(string)
		if file == "" {
			return agent.Output{"error": "policy_data or file is required"}, nil
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return agent.Output{"error": fmt.Sprintf("read policy: %v", err)}, nil
		}
		policyData = string(data)
	}

	var policy SCAPolicy
	if err := yaml.Unmarshal([]byte(policyData), &policy); err != nil {
		return agent.Output{"error": fmt.Sprintf("parse policy: %v", err)}, nil
	}

	for k, v := range policy.Variables {
		policyData = strings.ReplaceAll(policyData, k, v)
	}

	if ok, err := a.evaluateRequirements(policy.Requirements); err != nil || !ok {
		return agent.Output{
			"policy": policy.Policy.ID,
			"error":  "system does not meet policy requirements",
			"detail": fmt.Sprintf("%v", err),
		}, nil
	}

	var results []checkResult
	passCount, failCount := 0, 0

	for _, check := range policy.Checks {
		select {
		case <-ctx.Done():
			return agent.Output{"error": "cancelled", "results": results, "pass": passCount, "fail": failCount, "total": len(policy.Checks)}, nil
		default:
		}

		ok, errs := a.evaluateCheck(ctx, check)
		res := checkResult{
			ID:          check.ID,
			Title:       check.Title,
			Rationale:   check.Rationale,
			Remediation: check.Remediation,
			Compliance:  check.ComplianceMap(),
		}
		if ok {
			res.Status = "pass"
			passCount++
		} else {
			res.Status = "fail"
			res.Errors = errs
			failCount++
		}
		results = append(results, res)
	}

	policyID := policy.Policy.ID
	if policyID == "" {
		policyID, _ = input["policy_name"].(string)
	}

	return agent.Output{
		"policy":   policyID,
		"results":  results,
		"pass":     passCount,
		"fail":     failCount,
		"total":    len(policy.Checks),
		"score":    fmt.Sprintf("%.1f%%", float64(passCount)/float64(len(policy.Checks))*100),
	}, nil
}

func (a *Agent) evaluateRequirements(req struct {
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Condition   string   `yaml:"condition"`
	Rules       []string `yaml:"rules"`
}) (bool, error) {
	if len(req.Rules) == 0 {
		return true, nil
	}
	for _, rule := range req.Rules {
		ok, err := a.evaluateRule(context.Background(), rule)
		if err != nil {
			return false, err
		}
		if req.Condition == "all" && !ok {
			return false, nil
		}
		if req.Condition == "any" && ok {
			return true, nil
		}
	}
	return req.Condition != "any", nil
}

func (a *Agent) evaluateCheck(ctx context.Context, check SCACheck) (bool, []string) {
	if len(check.Rules) == 0 {
		return true, nil
	}

	var errs []string
	for _, rule := range check.Rules {
		ok, err := a.evaluateRule(ctx, rule)
		if err != nil {
			errs = append(errs, fmt.Sprintf("rule error: %v", err))
			if check.Condition == "all" {
				return false, errs
			}
			continue
		}
		if check.Condition == "all" && !ok {
			return false, append(errs, fmt.Sprintf("rule failed: %s", rule))
		}
		if check.Condition == "any" && ok {
			return true, nil
		}
	}
	return check.Condition != "any", errs
}

var allowedCmds = map[string]bool{
	"echo": true, "printf": true, "true": true, "hostname": true,
	"modprobe": true, "lsmod": true, "sysctl": true, "stat": true,
	"grep": true, "find": true, "ls": true, "cat": true, "head": true,
	"tail": true, "awk": true, "sed": true, "cut": true, "tr": true,
	"sort": true, "uniq": true, "wc": true, "id": true, "who": true,
	"last": true, "ps": true, "ss": true, "netstat": true, "sshd": true,
	"mount": true, "df": true, "getenforce": true, "sestatus": true,
	"systemctl": true, "service": true, "chkconfig": true,
	"pip": true, "pip3": true, "npm": true, "apt": true, "yum": true,
	"dnf": true, "dpkg": true, "rpm": true, "sha256sum": true,
	"openssl": true, "update-alternatives": true, "which": true,
	"apache2ctl": true, "httpd": true, "nginx": true, "mysqld": true,
	"postgres": true,
}

func (a *Agent) evaluateRule(ctx context.Context, rawRule string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rule := strings.TrimSpace(rawRule)
	negate := strings.HasPrefix(rule, "not ")
	if negate {
		rule = strings.TrimSpace(strings.TrimPrefix(rule, "not "))
	}

	switch {
	case strings.HasPrefix(rule, "c:"):
		// c:command -> r:expected_output
		parts := strings.SplitN(rule, "->", 2)
		cmdStr := strings.TrimSpace(strings.TrimPrefix(parts[0], "c:"))
		expected := ""
		if len(parts) > 1 {
			expected = strings.TrimSpace(strings.TrimPrefix(parts[1], "r:"))
		}

		cmdParts := strings.Fields(cmdStr)
		if len(cmdParts) == 0 {
			return false, fmt.Errorf("empty command")
		}
		if !allowedCmds[cmdParts[0]] {
			return false, fmt.Errorf("command not allowed: %s", cmdParts[0])
		}

		var cmd *exec.Cmd
		if len(cmdParts) == 1 {
			cmd = exec.CommandContext(ctx, cmdParts[0])
		} else {
			cmd = exec.CommandContext(ctx, cmdParts[0], cmdParts[1:]...)
		}
		output, err := cmd.Output()
		if err != nil {
			return false, nil
		}
		if expected == "" {
			return len(output) > 0, nil
		}
		matched, _ := regexp.MatchString(expected, string(output))
		return matched, nil

	case strings.HasPrefix(rule, "f:"):
		// f:/path -> r:content_regex
		parts := strings.SplitN(rule, "->", 2)
		path := strings.TrimSpace(strings.TrimPrefix(parts[0], "f:"))
		expected := ""
		if len(parts) > 1 {
			expected = strings.TrimSpace(strings.TrimPrefix(parts[1], "r:"))
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return negate, nil
		}
		if expected == "" {
			return !negate, nil
		}
		matched, _ := regexp.MatchString(expected, string(data))
		if negate {
			return !matched, nil
		}
		return matched, nil

	case strings.HasPrefix(rule, "d:"):
		// d:/dir -> r:file_regex -> r:content_regex
		parts := strings.SplitN(rule, "->", 3)
		dir := strings.TrimSpace(strings.TrimPrefix(parts[0], "d:"))
		fileRe := ""
		contentRe := ""
		if len(parts) > 1 {
			fileRe = strings.TrimSpace(strings.TrimPrefix(parts[1], "r:"))
		}
		if len(parts) > 2 {
			contentRe = strings.TrimSpace(strings.TrimPrefix(parts[2], "r:"))
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			return negate, nil
		}

		var fileRegex *regexp.Regexp
		if fileRe != "" {
			fileRegex, _ = regexp.Compile(fileRe)
		}
		var contentRegex *regexp.Regexp
		if contentRe != "" {
			contentRegex, _ = regexp.Compile(contentRe)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if fileRegex != nil && !fileRegex.MatchString(entry.Name()) {
				continue
			}
			if contentRegex != nil {
				data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
				if err != nil {
					continue
				}
				if contentRegex.Match(data) {
					if negate {
						return false, nil
					}
					return true, nil
				}
			} else if fileRegex == nil || fileRegex.MatchString(entry.Name()) {
				if negate {
					return false, nil
				}
				return true, nil
			}
		}
		if negate {
			return true, nil
		}
		return false, nil
	}

	return false, fmt.Errorf("unknown rule format: %s", rawRule)
}

func init() {
	_ = bufio.NewReader
	_ = time.Second
}
