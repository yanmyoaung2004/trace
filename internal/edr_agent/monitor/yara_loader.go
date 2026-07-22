package monitor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type ExternalRule struct {
	Name        string
	Description string
	Severity    Severity
	Pattern     *regexp.Regexp
	StringMatch string
}

type YaraLoader struct {
	externalDir string
	rules       []*YaraRule
	customRules []*ExternalRule
}

func NewYaraLoader() *YaraLoader {
	return &YaraLoader{}
}

func (yl *YaraLoader) SetExternalDir(dir string) {
	yl.externalDir = dir
}

func (yl *YaraLoader) Load() ([]*YaraRule, error) {
	var allRules []*YaraRule

	allRules = append(allRules, builtinYaraRules()...)

	if yl.externalDir != "" {
		external, err := yl.loadExternal()
		if err != nil {
			log.Printf("[yara-loader] external rules: %v (using built-in only)", err)
		} else {
			allRules = append(allRules, external...)
		}
	}

	yl.rules = allRules
	log.Printf("[yara-loader] total: %d rules (%d built-in + %d external)",
		len(allRules), len(builtinYaraRules()), len(allRules)-len(builtinYaraRules()))
	return allRules, nil
}

func (yl *YaraLoader) loadExternal() ([]*YaraRule, error) {
	entries, err := os.ReadDir(yl.externalDir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", yl.externalDir, err)
	}

	var rules []*YaraRule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".yar") {
			continue
		}
		path := filepath.Join(yl.externalDir, entry.Name())
		loaded, err := yl.parseYaraFile(path)
		if err != nil {
			log.Printf("[yara-loader] skip %s: %v", entry.Name(), err)
			continue
		}
		rules = append(rules, loaded...)
	}

	return rules, nil
}

func (yl *YaraLoader) parseYaraFile(path string) ([]*YaraRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	var rules []*YaraRule

	ruleBlocks := splitYaraRules(content)
	for _, block := range ruleBlocks {
		rule := yl.parseRuleBlock(block)
		if rule != nil {
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

func splitYaraRules(content string) []string {
	var blocks []string
	depth := 0
	start := -1

	for i := 0; i < len(content); i++ {
		c := content[i]
		if c == '{' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 && start >= 0 {
				blocks = append(blocks, content[start:i+1])
				start = -1
			}
		}
	}
	return blocks
}

func (yl *YaraLoader) parseRuleBlock(block string) *YaraRule {
	rule := &YaraRule{}

	rule.Name = extractRuleName(block)
	if rule.Name == "" {
		return nil
	}

	rule.Description = extractMetaValue(block, "description")
	if rule.Description == "" {
		rule.Description = rule.Name
	}

	sevStr := extractMetaValue(block, "severity")
	switch strings.ToLower(sevStr) {
	case "critical", "alert":
		rule.Severity = SeverityCritical
	case "high", "warning":
		rule.Severity = SeverityWarning
	case "medium":
		rule.Severity = SeverityInfo
	default:
		rule.Severity = SeverityInfo
	}

	matcher := buildMatcher(block)
	if matcher == nil {
		return nil
	}
	rule.Matcher = matcher

	return rule
}

func extractRuleName(block string) string {
	re := regexp.MustCompile(`rule\s+(\w+)`)
	matches := re.FindStringSubmatch(block)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractMetaValue(block, key string) string {
	re := regexp.MustCompile(key + `\s*=\s*"([^"]*)"`)
	matches := re.FindStringSubmatch(block)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractStringPatterns(block string) []string {
	var patterns []string
	re := regexp.MustCompile(`\$(\w+)\s*=\s*"([^"]*)"`)
	matches := re.FindAllStringSubmatch(block, -1)
	for _, m := range matches {
		if len(m) > 2 {
			patterns = append(patterns, m[2])
		}
	}
	return patterns
}

func extractHexPatterns(block string) []string {
	var patterns []string
	re := regexp.MustCompile(`\$(\w+)\s*=\s*\{([^}]*)\}`)
	matches := re.FindAllStringSubmatch(block, -1)
	for _, m := range matches {
		if len(m) > 2 {
			hex := strings.ReplaceAll(m[2], " ", "")
			hex = strings.ReplaceAll(hex, "\n", "")
			hex = strings.ReplaceAll(hex, "\t", "")
			if len(hex) > 4 {
				decoded := decodeHexPattern(hex)
				if decoded != "" {
					patterns = append(patterns, decoded)
				}
			}
		}
	}
	return patterns
}

func decodeHexPattern(hex string) string {
	if len(hex)%2 != 0 {
		return ""
	}
	var result []byte
	for i := 0; i < len(hex); i += 2 {
		if hex[i] == '?' || hex[i+1] == '?' {
			continue
		}
		var b byte
		fmt.Sscanf(hex[i:i+2], "%02x", &b)
		result = append(result, b)
	}
	return string(result)
}

func buildMatcher(block string) yaraMatch {
	patterns := extractStringPatterns(block)
	if len(patterns) == 0 {
		patterns = extractHexPatterns(block)
	}

	if len(patterns) > 0 {
		if len(patterns) == 1 {
			return yaraString{[]byte(patterns[0])}
		}
		// Multiple patterns: use regex with alternation
		reStr := "(?i)(" + strings.Join(escapeForRegex(patterns), "|") + ")"
		re, err := regexp.Compile(reStr)
		if err == nil {
			return yaraRegex{re}
		}
		return yaraString{[]byte(patterns[0])}
	}

	return nil
}

func escapeForRegex(patterns []string) []string {
	result := make([]string, len(patterns))
	re := regexp.MustCompile(`[.+*?^${}()|\[\]\\]`)
	for i, p := range patterns {
		result[i] = re.ReplaceAllString(p, `\`+string(p[0]))
	}
	return result
}
