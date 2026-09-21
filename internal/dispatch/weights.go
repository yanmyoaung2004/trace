package dispatch

// Scoring weights as data (FIX_PLAN 1.1: scoring.weights.yaml). The ladder
// values live in the YAML file; this loader reads them with boring fallback
// defaults identical to the historic ladder. Calibration tests pin behavior.

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ScoringWeights holds the confidence ladder.
type ScoringWeights struct {
	MaliciousReputation   float64 `yaml:"malicious_reputation"`
	SuspiciousReputation  float64 `yaml:"suspicious_reputation"`
	VTThresholdRatio      float64 `yaml:"vt_threshold_ratio"`
	VTScore               float64 `yaml:"vt_score"`
	CountScore            float64 `yaml:"count_score"`
	FoundScore            float64 `yaml:"found_score"`
	SuspiciousListScore   float64 `yaml:"suspicious_list_score"`
	IntelBuiltinScore     float64 `yaml:"intel_builtin_score"`
	ErrorScore            float64 `yaml:"error_score"`
	NotConfiguredScore    float64 `yaml:"not_configured_score"`
	DefaultScore          float64 `yaml:"default_score"`
	PromptVersion         int     `yaml:"prompt_version"`
}

func defaultWeights() ScoringWeights {
	return ScoringWeights{
		MaliciousReputation:  0.95,
		SuspiciousReputation: 0.7,
		VTThresholdRatio:     0.3,
		VTScore:              0.9,
		CountScore:           0.85,
		FoundScore:           0.75,
		SuspiciousListScore:  0.8,
		IntelBuiltinScore:    0.8,
		ErrorScore:           0.1,
		NotConfiguredScore:   0,
		DefaultScore:         0.5,
		PromptVersion:        1,
	}
}

var activeWeights = defaultWeights()

// LoadScoringWeights loads scoring.weights.yaml (missing file = defaults).
func LoadScoringWeights(path string) (ScoringWeights, error) {
	w := defaultWeights()
	if path == "" {
		activeWeights = w
		return w, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			activeWeights = w
			return w, nil
		}
		return w, err
	}
	if err := yaml.Unmarshal(data, &w); err != nil {
		return activeWeights, err
	}
	activeWeights = w
	return w, nil
}
