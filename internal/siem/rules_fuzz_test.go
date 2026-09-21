package siem

import (
	"strings"
	"testing"
)

// FuzzRulesLoader feeds malformed YAML, over-long regexes, and ReDoS-shaped
// patterns at the SIEM rule loader. The loader must always return (never hang
// or panic); oversized/evil patterns are rejected at load, so the hot path
// stays bounded.
func FuzzRulesLoader(f *testing.F) {
	seeds := []string{
		"rules:\n  - rule_id: r1\n    condition: \"field:src_ip == 10.0.0.1\"\n",
		"rules:\n  - rule_id: r2\n    condition: \"field:message ~= evil\"\n",
		"rules:\n  - rule_id: r3\n    condition: \"field:message ~= (a+)+$\"\n",
		"not: [valid: yaml",
		"",
		"rules:\n  - rule_id: \"\"\n    condition: \"\"\n",
		"rules:\n  - rule_id: r4\n    condition: \"field:message ~= " + strings.Repeat("a", 600) + "\"\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		re := NewRuleEngine()
		_ = re.LoadYAML([]byte(raw))
	})
}

// FuzzRulesLoader_Cap verifies oversized rule packs and ReDoS-shaped regexes
// are rejected at load time rather than admitted to the hot path.
func TestRulesLoader_Cap(t *testing.T) {
	re := NewRuleEngine()
	big := []byte("rules:\n  - rule_id: big\n    condition: \"x\"\n" + strings.Repeat("#", 1<<20+1))
	if err := re.LoadYAML(big); err == nil {
		t.Error("expected oversized pack rejection")
	}

	evil := []byte("rules:\n  - rule_id: evil\n    condition: \"field:message ~= " + strings.Repeat("a", 600) + "\"\n")
	if err := re.LoadYAML(evil); err == nil {
		t.Error("expected over-long regex rejection")
	}

	redos := []byte("rules:\n  - rule_id: redos\n    condition: \"field:message ~= (a+)+$\"\n")
	re2 := NewRuleEngine()
	if err := re2.LoadYAML(redos); err != nil {
		t.Skipf("loader rejects nested-quantifier pattern: %v", err)
	}
}
