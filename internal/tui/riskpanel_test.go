package tui

import (
	"strings"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/asset"
)

func scoredSample() []asset.ScoredAsset {
	assets := []asset.Asset{
		{ID: "db-01", Hostname: "db-01", Type: asset.TypeDatabase, Criticality: 10},
		{ID: "web-01", Hostname: "web-01", Type: asset.TypeHost, Criticality: 6},
	}
	vulns := []asset.Vuln{
		{CVEID: "CVE-2024-0001", CVSS: 9.8, Severity: "critical", AssetID: "db-01"},
	}
	return asset.Join(assets, vulns)
}

func TestAssetRiskPanel_Rows(t *testing.T) {
	out := AssetRiskPanel(scoredSample(), 10)
	for _, want := range []string{"Asset Risk", "db-01", "web-01", "CRITICAL", "vulns"} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("panel missing %q:\n%s", want, out)
		}
	}
	// Highest-risk asset sorts first.
	dbIdx := strings.Index(out, "db-01")
	webIdx := strings.Index(out, "web-01")
	if dbIdx < 0 || webIdx < 0 || dbIdx > webIdx {
		t.Errorf("db-01 should rank above web-01:\n%s", out)
	}
}

func TestAssetRiskPanel_Empty(t *testing.T) {
	out := AssetRiskPanel(nil, 10)
	if !strings.Contains(out, "No assets inventoried") {
		t.Errorf("empty panel should say so:\n%s", out)
	}
}

func TestAssetRiskPanel_MaxRows(t *testing.T) {
	var items []asset.ScoredAsset
	for i := 0; i < 5; i++ {
		items = append(items, asset.Score(
			asset.Asset{ID: string(rune('a' + i)), Hostname: "h", Type: asset.TypeHost},
			nil))
	}
	out := AssetRiskPanel(items, 2)
	if strings.Count(out, "\n") > 5 { // header + title + 2 rows + margin
		t.Errorf("maxRows=2 not honored:\n%s", out)
	}
}
