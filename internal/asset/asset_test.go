package asset

import (
	"testing"
)

func TestNormalizeType(t *testing.T) {
	cases := map[string]AssetType{
		"host": TypeHost, "HOST": TypeHost, " container ": TypeContainer,
		"vm": TypeVM, "service": TypeService, "database": TypeDatabase,
		"network": TypeNetwork, "user": TypeUser,
		"": TypeUnknown, "laptop": TypeUnknown, "k8s-pod": TypeUnknown,
	}
	for in, want := range cases {
		if got := NormalizeType(in); got != want {
			t.Errorf("NormalizeType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScore_NoVulnsBaseline(t *testing.T) {
	a := Asset{ID: "a1", Hostname: "web-01", Type: TypeHost, Criticality: 8}
	s := Score(a, nil)
	if s.VulnCount != 0 {
		t.Errorf("VulnCount = %d, want 0", s.VulnCount)
	}
	if s.RiskScore != 16 { // crit*2 baseline
		t.Errorf("RiskScore = %.1f, want 16", s.RiskScore)
	}
	if s.RiskBand != "low" {
		t.Errorf("RiskBand = %q, want low", s.RiskBand)
	}
}

func TestScore_CriticalFinding(t *testing.T) {
	a := Asset{ID: "a1", Hostname: "db-01", Type: TypeDatabase, Criticality: 10}
	v := []Vuln{{CVEID: "CVE-2024-0001", CVSS: 9.8, Severity: "critical", AssetID: "a1"}}
	s := Score(a, v)
	if s.MaxCVSS != 9.8 {
		t.Errorf("MaxCVSS = %.1f, want 9.8", s.MaxCVSS)
	}
	if s.RiskBand != "critical" {
		t.Errorf("RiskBand = %q, want critical (score %.1f)", s.RiskBand, s.RiskScore)
	}
	if s.RiskScore > 100 || s.RiskScore < 0 {
		t.Errorf("RiskScore %.1f out of range", s.RiskScore)
	}
}

func TestScore_CriticalityScales(t *testing.T) {
	v := []Vuln{{CVEID: "CVE-2024-0002", CVSS: 7.5, Severity: "high", AssetID: "x"}}
	lo := Score(Asset{ID: "x", Criticality: 0}, v)
	hi := Score(Asset{ID: "x", Criticality: 10}, v)
	if !(hi.RiskScore > lo.RiskScore) {
		t.Errorf("higher criticality should score higher: lo=%.1f hi=%.1f", lo.RiskScore, hi.RiskScore)
	}
}

func TestScore_CountPressure(t *testing.T) {
	mk := func(n int) []Vuln {
		out := make([]Vuln, n)
		for i := range out {
			out[i] = Vuln{CVEID: "CVE-2024-1000", CVSS: 5.0, Severity: "medium", AssetID: "x"}
		}
		return out
	}
	a := Asset{ID: "x", Criticality: 5}
	one := Score(a, mk(1))
	many := Score(a, mk(6))
	if !(many.RiskScore > one.RiskScore) {
		t.Errorf("more vulns should score higher: one=%.1f many=%.1f", one.RiskScore, many.RiskScore)
	}
}

func TestBand_Boundaries(t *testing.T) {
	cases := map[float64]string{
		0: "low", 29.9: "low", 30: "medium", 59.9: "medium",
		60: "high", 79.9: "high", 80: "critical", 100: "critical",
	}
	for score, want := range cases {
		if got := Band(score); got != want {
			t.Errorf("Band(%.1f) = %q, want %q", score, got, want)
		}
	}
}

func TestJoin_SortsByRiskDescending(t *testing.T) {
	assets := []Asset{
		{ID: "clean", Hostname: "clean-01", Type: TypeHost, Criticality: 2},
		{ID: "bad", Hostname: "bad-01", Type: TypeHost, Criticality: 9},
		{ID: "mid", Hostname: "mid-01", Type: TypeService, Criticality: 5},
	}
	vulns := []Vuln{
		{CVEID: "CVE-2024-0001", CVSS: 9.8, Severity: "critical", AssetID: "bad"},
		{CVEID: "CVE-2024-0002", CVSS: 4.3, Severity: "medium", AssetID: "mid"},
		{CVEID: "CVE-2024-9999", CVSS: 10, Severity: "critical", AssetID: "ghost"},
		{CVEID: "CVE-2024-0003", CVSS: 5.0, Severity: "low", AssetID: ""},
	}
	got := Join(assets, vulns)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (ghost + empty-asset vulns ignored)", len(got))
	}
	if got[0].ID != "bad" || got[1].ID != "mid" || got[2].ID != "clean" {
		t.Errorf("order = %s,%s,%s, want bad,mid,clean",
			got[0].ID, got[1].ID, got[2].ID)
	}
	if got[0].VulnCount != 1 || got[2].VulnCount != 0 {
		t.Errorf("vuln counts = %d,%d want 1,0", got[0].VulnCount, got[2].VulnCount)
	}
}

func TestJoin_SkipsMalformedAssets(t *testing.T) {
	assets := []Asset{{Hostname: "no-id"}, {ID: "ok", Hostname: "ok-01"}}
	got := Join(assets, nil)
	if len(got) != 1 || got[0].ID != "ok" {
		t.Errorf("expected only ok asset, got %+v", got)
	}
}

func TestTriageLine(t *testing.T) {
	s := Score(Asset{ID: "a1", Hostname: "web-01", Type: TypeHost, Criticality: 9},
		[]Vuln{{CVEID: "CVE-2024-0001", CVSS: 9.1, Severity: "critical", AssetID: "a1"}})
	line := s.TriageLine()
	for _, want := range []string{"web-01", "host", "vulns=1", "9.1"} {
		if !containsStr(line, want) {
			t.Errorf("TriageLine %q missing %q", line, want)
		}
	}
}

func containsStr(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
