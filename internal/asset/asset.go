// Package asset implements the Phase 4 minimal-viable asset inventory with
// vulnerability join and risk scoring. All types are new and additive:
// no existing tables, routes, or semantics are changed. Persistence is
// intentionally in-memory/file-local; server DB ownership stays with the
// ServerTrust owner (new tables there would be additive CREATE IF NOT
// EXISTS only, coordinated via hub).
package asset

import (
	"fmt"
	"sort"
	"strings"
)

// AssetType classifies an inventoried entity.
type AssetType string

const (
	TypeHost      AssetType = "host"
	TypeContainer AssetType = "container"
	TypeVM        AssetType = "vm"
	TypeService   AssetType = "service"
	TypeDatabase  AssetType = "database"
	TypeNetwork   AssetType = "network"
	TypeUser      AssetType = "user"
	TypeUnknown   AssetType = "unknown"
)

// NormalizeType maps free-form input to a known AssetType.
func NormalizeType(s string) AssetType {
	switch AssetType(strings.ToLower(strings.TrimSpace(s))) {
	case TypeHost, TypeContainer, TypeVM, TypeService, TypeDatabase, TypeNetwork, TypeUser:
		return AssetType(strings.ToLower(strings.TrimSpace(s)))
	default:
		return TypeUnknown
	}
}

// Asset is a single inventoried entity.
type Asset struct {
	ID          string    `json:"id"`
	Hostname    string    `json:"hostname"`
	IP          string    `json:"ip,omitempty"`
	OS          string    `json:"os,omitempty"`
	Type        AssetType `json:"type"`
	Criticality float64   `json:"criticality"` // 0..10 business criticality
	Owner       string    `json:"owner,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
}

// Vuln is a vulnerability finding attached to an asset (e.g. from the
// EDR vuln scanner or CVE enrichment). Kept local so internal/asset has
// no import cycle with internal/edr_agent.
type Vuln struct {
	CVEID       string  `json:"cve_id"`
	PackageName string  `json:"package_name,omitempty"`
	Installed   string  `json:"installed,omitempty"`
	FixedIn     string  `json:"fixed_in,omitempty"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	AssetID     string  `json:"asset_id"`
}

// ScoredAsset is an asset joined with its vulns plus a computed risk score.
type ScoredAsset struct {
	Asset
	Vulns     []Vuln  `json:"vulns"`
	RiskScore float64 `json:"risk_score"` // 0..100
	RiskBand  string  `json:"risk_band"`  // low|medium|high|critical
	MaxCVSS   float64 `json:"max_cvss"`
	VulnCount int     `json:"vuln_count"`
}

// severityWeight maps severity labels to 0..1 multipliers.
func severityWeight(s string) float64 {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 1.0
	case "high":
		return 0.75
	case "medium":
		return 0.5
	case "low":
		return 0.25
	default:
		return 0.4
	}
}

// Score computes a 0..100 risk score for one asset from its vulns and
// criticality. Deterministic, no I/O:
//
//	risk = clamp( maxCVSS*10*w(sev) blended with vuln-count pressure,
//	              scaled by (0.5 + criticality/20) )
//
// Empty vuln set yields a baseline from criticality alone so clean assets
// still triage-rank below exposed ones.
func Score(a Asset, vulns []Vuln) ScoredAsset {
	crit := a.Criticality
	if crit < 0 {
		crit = 0
	}
	if crit > 10 {
		crit = 10
	}
	out := ScoredAsset{Asset: a, Vulns: append([]Vuln(nil), vulns...), VulnCount: len(vulns)}
	if len(vulns) == 0 {
		out.RiskScore = crit * 2 // 0..20 baseline
		out.RiskBand = Band(out.RiskScore)
		return out
	}
	maxCVSS := 0.0
	topW := 0.0
	for _, v := range vulns {
		if v.CVSS > maxCVSS {
			maxCVSS = v.CVSS
		}
		if w := severityWeight(v.Severity); w > topW {
			topW = w
		}
	}
	out.MaxCVSS = maxCVSS
	// Base from worst finding.
	base := maxCVSS * 10 * (0.6 + 0.4*topW)
	// Count pressure: each extra vuln adds diminishing weight, capped.
	pressure := 0.0
	for i := 1; i < len(vulns); i++ {
		pressure += 3.0 / float64(i+1)
	}
	if pressure > 15 {
		pressure = 15
	}
	// Criticality scales the score: crit 0 -> 0.75x, crit 10 -> 1.0x.
	scale := 0.75 + crit/40 // crit 0 -> 0.75, crit 10 -> 1.0
	score := (base + pressure) * scale
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	// Round to 1 decimal.
	out.RiskScore = float64(int(score*10+0.5)) / 10
	out.RiskBand = Band(out.RiskScore)
	return out
}

// Band maps a 0..100 score to a triage band.
func Band(score float64) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

// Join attaches vulns to assets by AssetID and scores each asset.
// Unknown AssetIDs are ignored (no phantom assets). Result is sorted
// by RiskScore descending for triage consumption.
func Join(assets []Asset, vulns []Vuln) []ScoredAsset {
	byAsset := make(map[string][]Vuln, len(assets))
	for _, v := range vulns {
		if v.AssetID == "" {
			continue
		}
		byAsset[v.AssetID] = append(byAsset[v.AssetID], v)
	}
	out := make([]ScoredAsset, 0, len(assets))
	for _, a := range assets {
		if a.ID == "" {
			continue // skip malformed entries; never poison the whole triage list
		}
		out = append(out, Score(a, byAsset[a.ID]))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RiskScore == out[j].RiskScore {
			return out[i].ID < out[j].ID
		}
		return out[i].RiskScore > out[j].RiskScore
	})
	return out
}

// TriageLine renders one scored asset for CLI/triage output.
func (s ScoredAsset) TriageLine() string {
	host := s.Hostname
	if host == "" {
		host = s.ID
	}
	return fmt.Sprintf("%-8s %5.1f  %-16s %-10s vulns=%d maxCVSS=%.1f",
		strings.ToUpper(s.RiskBand), s.RiskScore, host, s.Type, s.VulnCount, s.MaxCVSS)
}
