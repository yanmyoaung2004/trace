package detection

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type YaraRule struct {
	Name      string
	Condition string
	Patterns  []YaraPattern
	Meta      map[string]string
}

type YaraPattern struct {
	Type      string
	Value     string
	CaseSensitive bool
	Hex       []byte
	HexMask   []byte
	Regex     *regexp.Regexp
}

type YaraMatch struct {
	Rule      string `json:"rule"`
	Meta      map[string]string `json:"meta"`
	Matched   string `json:"matched"`
	Offset    int64  `json:"offset"`
}

type YaraScanner struct {
	rules []YaraRule
}

func NewYaraScanner() *YaraScanner {
	return &YaraScanner{}
}

func (ys *YaraScanner) LoadRules(rules []YaraRule) {
	ys.rules = rules
}

func (ys *YaraScanner) LoadEmbedded() {
	ys.rules = defaultRules
}

func (ys *YaraScanner) ScanFile(path string) ([]YaraMatch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return ys.ScanBytes(data), nil
}

func (ys *YaraScanner) ScanBytes(data []byte) []YaraMatch {
	var matches []YaraMatch

	for _, rule := range ys.rules {
		match := ys.evaluate(rule, data)
		if match != nil {
			matches = append(matches, *match)
		}
	}

	return matches
}

func (ys *YaraScanner) evaluate(rule YaraRule, data []byte) *YaraMatch {
	var matchedPattern string
	var matchedOffset int64 = -1

	for _, p := range rule.Patterns {
		var found bool
		var offset int64

		switch p.Type {
		case "string":
			offset, found = matchString(data, p.Value, p.CaseSensitive)
		case "hex":
			offset, found = matchHex(data, p.Hex, p.HexMask)
		case "regex":
			offset, found = matchRegex(data, p.Regex)
		case "pe_import":
			offset, found = matchPEImport(data, p.Value)
		case "pe_section":
			offset, found = matchPESection(data, p.Value)
		}

		if found {
			if matchedOffset == -1 || offset < matchedOffset {
				matchedOffset = offset
				matchedPattern = p.Value
			}
		} else if !isConditional(rule.Condition) {
			return nil
		}
	}

	if matchedOffset >= 0 {
		if rule.Condition == "any" || strings.Contains(rule.Condition, fmt.Sprintf("%d", countPatterns(data, rule.Patterns))) || evaluateCondition(rule.Condition, len(rule.Patterns)) {
			return &YaraMatch{
				Rule:    rule.Name,
				Meta:    rule.Meta,
				Matched: matchedPattern,
				Offset:  matchedOffset,
			}
		}
	}

	return nil
}

func matchString(data []byte, pattern string, caseSensitive bool) (int64, bool) {
	var search []byte
	if caseSensitive {
		search = []byte(pattern)
	} else {
		search = []byte(strings.ToLower(pattern))
		src := bytes.ToLower(data)
		idx := bytes.Index(src, search)
		if idx >= 0 {
			return int64(idx), true
		}
		return 0, false
	}
	idx := bytes.Index(data, search)
	if idx >= 0 {
		return int64(idx), true
	}
	return 0, false
}

func matchHex(data []byte, pattern, mask []byte) (int64, bool) {
	if len(pattern) > len(data) {
		return 0, false
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if mask != nil && mask[j] == 0 {
				continue
			}
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return int64(i), true
		}
	}
	return 0, false
}

func matchRegex(data []byte, re *regexp.Regexp) (int64, bool) {
	loc := re.FindIndex(data)
	if loc != nil {
		return int64(loc[0]), true
	}
	return 0, false
}

func matchPEImport(data []byte, importName string) (int64, bool) {
	if !isPE(data) {
		return 0, false
	}

	imports, err := parsePEImportTable(data)
	if err != nil {
		return 0, false
	}

	lower := strings.ToLower(importName)
	for _, imp := range imports {
		if strings.Contains(strings.ToLower(imp), lower) {
			return 0, true
		}
	}
	return 0, false
}

func matchPESection(data []byte, sectionName string) (int64, bool) {
	if !isPE(data) {
		return 0, false
	}

	sections, err := parsePESections(data)
	if err != nil {
		return 0, false
	}

	lower := strings.ToLower(sectionName)
	for _, s := range sections {
		if strings.Contains(strings.ToLower(s.Name), lower) {
			return int64(s.Offset), true
		}
	}
	return 0, false
}

func isConditional(condition string) bool {
	return strings.Contains(condition, "all") || strings.Contains(condition, "any") || strings.HasPrefix(condition, "$")
}

func countPatterns(data []byte, patterns []YaraPattern) int {
	count := 0
	for _, p := range patterns {
		switch p.Type {
		case "string":
			_, found := matchString(data, p.Value, p.CaseSensitive)
			if found {
				count++
			}
		case "hex":
			_, found := matchHex(data, p.Hex, p.HexMask)
			if found {
				count++
			}
		case "regex":
			_, found := matchRegex(data, p.Regex)
			if found {
				count++
			}
		}
	}
	return count
}

func evaluateCondition(cond string, total int) bool {
	cond = strings.TrimSpace(cond)

	if strings.HasPrefix(cond, "all of them") || strings.HasPrefix(cond, "all") {
		return false
	}

	if strings.HasPrefix(cond, "any of them") || strings.HasPrefix(cond, "any") {
		return false
	}

	if total > 0 {
		return true
	}

	return false
}

func isPE(data []byte) bool {
	if len(data) < 64 {
		return false
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return false
	}

	eLfanew := int64(binary.LittleEndian.Uint32(data[60:64]))
	if eLfanew+4 >= int64(len(data)) {
		return false
	}
	if data[eLfanew] != 'P' || data[eLfanew+1] != 'E' {
		return false
	}
	if data[eLfanew+2] != 0 || data[eLfanew+3] != 0 {
		return false
	}
	return true
}

func initYaraRule(name, condition string, patterns ...YaraPattern) YaraRule {
	return YaraRule{
		Name:      name,
		Condition: condition,
		Patterns:  patterns,
	}
}

func stringPat(value string, caseSensitive bool) YaraPattern {
	return YaraPattern{
		Type:          "string",
		Value:         value,
		CaseSensitive: caseSensitive,
	}
}

func hexPat(hex string) YaraPattern {
	h := strings.ReplaceAll(hex, " ", "")
	h = strings.ReplaceAll(h, "?", "00")
	data := make([]byte, len(h)/2)
	for i := 0; i < len(data); i++ {
		fmt.Sscanf(h[i*2:i*2+2], "%02x", &data[i])
	}
	return YaraPattern{
		Type: "hex",
		Hex:  data,
	}
}

func importPat(name string) YaraPattern {
	return YaraPattern{
		Type:  "pe_import",
		Value: name,
	}
}

func sectionPat(name string) YaraPattern {
	return YaraPattern{
		Type:  "pe_section",
		Value: name,
	}
}

func init() {
	_ = filepath.Join
}
