package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/yanmyoaung2004/trace/internal/asset"
)

// newAssetCmd is the read-only asset inventory CLI. It consumes the
// file-local inventory (internal/asset) through Join + Score and never
// touches existing tables, routes, or commands.
func newAssetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "asset",
		Short: "Manage asset inventory and risk scoring",
		Long: `Inspect file-local asset inventory joined with vulnerabilities and risk scores.

Inventory file shape (default ~/.trace/assets.json):
  {"assets":[{"id":"web-01","hostname":"web-01","type":"host","criticality":8}],
   "vulns":[{"cve_id":"CVE-2024-0001","cvss":9.8,"severity":"critical","asset_id":"web-01"}]}

Examples:
  trace asset list
  trace asset list --type host --min-risk 60
  trace asset list --format json --inventory ./assets.json`,
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List scored assets (asset → vuln → risk)",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			invPath, _ := cmdCobra.Flags().GetString("inventory")
			if invPath == "" {
				invPath = asset.DefaultInventoryPath()
			}
			format, _ := cmdCobra.Flags().GetString("format")
			typeFilter, _ := cmdCobra.Flags().GetString("type")
			minRisk, _ := cmdCobra.Flags().GetFloat64("min-risk")

			assets, vulns, err := asset.LoadInventory(invPath)
			if err != nil {
				return err
			}
			scored := asset.Join(assets, vulns)

			var rows []asset.ScoredAsset
			for _, s := range scored {
				if typeFilter != "" && string(s.Type) != string(asset.NormalizeType(typeFilter)) {
					continue
				}
				if s.RiskScore < minRisk {
					continue
				}
				rows = append(rows, s)
			}
			if len(rows) == 0 {
				outln(cmdCobra, "No assets match.")
				return nil
			}

			w := out(cmdCobra)
			switch format {
			case "table":
				tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
				fmt.Fprintln(tw, "RISK\tSCORE\tASSET\tTYPE\tVULNS\tMAX CVSS")
				for _, s := range rows {
					host := s.Hostname
					if host == "" {
						host = s.ID
					}
					fmt.Fprintf(tw, "%s\t%.1f\t%s\t%s\t%d\t%.1f\n",
						s.RiskBand, s.RiskScore, host, s.Type, s.VulnCount, s.MaxCVSS)
				}
				tw.Flush()
			case "json":
				data, err := json.MarshalIndent(rows, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal assets: %w", err)
				}
				fmt.Fprintln(w, string(data))
			case "csv":
				cw := csv.NewWriter(w)
				_ = cw.Write([]string{"id", "hostname", "type", "criticality", "risk_score", "risk_band", "vuln_count", "max_cvss"})
				for _, s := range rows {
					_ = cw.Write([]string{
						s.ID, s.Hostname, string(s.Type),
						fmt.Sprintf("%.1f", s.Criticality),
						fmt.Sprintf("%.1f", s.RiskScore), s.RiskBand,
						fmt.Sprintf("%d", s.VulnCount),
						fmt.Sprintf("%.1f", s.MaxCVSS),
					})
				}
				cw.Flush()
				if err := cw.Error(); err != nil {
					return fmt.Errorf("write csv: %w", err)
				}
			default:
				return fmt.Errorf("unknown format %q (want table|json|csv)", format)
			}
			return nil
		},
	}
	listCmd.Flags().String("inventory", "", "path to inventory JSON (default ~/.trace/assets.json)")
	listCmd.Flags().String("format", "table", "output format: table|json|csv")
	listCmd.Flags().String("type", "", "filter by asset type (host, container, vm, service, database, network, user)")
	listCmd.Flags().Float64("min-risk", 0, "minimum risk score (0-100)")

	cmd.AddCommand(listCmd)
	return cmd
}
