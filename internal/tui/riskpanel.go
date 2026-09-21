package tui

import (
	"fmt"
	"strings"

	"github.com/yanmyoaung2004/trace/internal/asset"
)

// AssetRiskPanel renders a read-only asset → vuln → risk summary table.
// Pure function over already-scored assets: no I/O, no App interface change,
// no writes. Main can embed it in the dashboard when ready.
func AssetRiskPanel(items []asset.ScoredAsset, maxRows int) string {
	var b strings.Builder
	b.WriteString(SecondaryTitleStyle.Render("Asset Risk") + "\n")
	if len(items) == 0 {
		b.WriteString("  No assets inventoried.\n")
		return b.String()
	}
	if maxRows <= 0 {
		maxRows = 10
	}
	if len(items) > maxRows {
		items = items[:maxRows]
	}
	b.WriteString("  RISK      SCORE  ASSET            TYPE        VULNS  MAX CVSS\n")
	for _, s := range items {
		host := s.Hostname
		if host == "" {
			host = s.ID
		}
		if len(host) > 16 {
			host = host[:15] + "…"
		}
		b.WriteString(fmt.Sprintf("  %-9s %5.1f  %-16s %-11s %5d  %8.1f\n",
			strings.ToUpper(s.RiskBand), s.RiskScore, host, s.Type,
			s.VulnCount, s.MaxCVSS))
	}
	return b.String()
}
