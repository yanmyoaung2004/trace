// Package siem severity scale.
//
// Single severity scale shared by SIEM rules, auto-case creation, the
// dashboard, and alert lifecycle code. Rule authors write severities in
// the 0-5 range; every other scale maps through here so thresholds agree.
//
// Cross-scale mapping table (authoritative):
//
//	Rules (this package):  0-5   (0=info … 5=critical)
//	Monitor events:        1/3/5/7 (info/warning/alert/critical)
//	Dashboard legacy:      7+ critical, 4-6 high (see NormalizeMonitor)
//	Auto-case threshold:   rule severity >= 4 creates a case
package siem

// Severity bounds for rule severities.
const (
	MinSeverity = 0
	MaxSeverity = 5
)

// SeverityLabel maps a rule severity (0-5) to a case/dashboard label.
// Out-of-range values clamp to the nearest bound.
func SeverityLabel(sev int) string {
	if sev < 0 {
		sev = 0
	}
	if sev > MaxSeverity {
		sev = MaxSeverity
	}
	switch {
	case sev <= 1:
		return "low"
	case sev <= 3:
		return "medium"
	case sev == 4:
		return "high"
	default:
		return "critical"
	}
}

// NormalizeMonitor maps a monitor severity (1/3/5/7) onto the 0-5 rule
// scale so both pipelines share thresholds.
func NormalizeMonitor(msev int) int {
	switch {
	case msev <= 1:
		return 1
	case msev <= 3:
		return 2
	case msev <= 5:
		return 4
	default:
		return 5
	}
}

// ShouldAutoCase reports whether a rule severity must open a case.
// Single threshold shared with serve auto-case wiring.
func ShouldAutoCase(ruleSev int) bool { return ruleSev >= 4 }

// ClampSeverity clamps an arbitrary severity into [0,5].
func ClampSeverity(sev int) int {
	if sev < MinSeverity {
		return MinSeverity
	}
	if sev > MaxSeverity {
		return MaxSeverity
	}
	return sev
}
