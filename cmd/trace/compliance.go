package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/yanmyoaung2004/trace/internal/compliance"
	"github.com/yanmyoaung2004/trace/internal/plugins/sca"
	"github.com/yanmyoaung2004/trace/internal/tui"
	"github.com/spf13/cobra"
)

var complianceEngine *compliance.ReportEngine

func newComplianceCmd() *cobra.Command {
	complianceEngine = compliance.NewReportEngine(sca.New())

	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Run compliance scans and generate audit-ready reports (GDPR, HIPAA, PCI, NIST, ISO 27001, SOC 2)",
		Long: `Run compliance scans and generate audit-ready reports.

Frameworks:
  pci_dss_v4.0   PCI DSS v4.0 (12 requirements)
  pci_dss_v3.2.1 PCI DSS v3.2.1
  hipaa          HIPAA Security Rule
  gdpr           GDPR
  nist_sp_800-53 NIST SP 800-53 Rev.5
  iso_27001-2013 ISO 27001:2013
  soc_2          SOC 2
  cis_csc_v8     CIS Critical Security Controls v8

Examples:
  trace compliance report --framework pci_dss_v4.0
  trace compliance assess --framework pci_dss_v4.0 --control 1.2.5 --status pass
  trace compliance evidence --framework hipaa --control 164.312 --file audit-log.txt
  trace compliance frameworks`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			return cmdCobra.Help()
		},
	}

	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a compliance report for a framework",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			framework, _ := cmdCobra.Flags().GetString("framework")
			output, _ := cmdCobra.Flags().GetString("output")

			if framework == "" {
				if tui.IsInteractive() {
					p := tui.NewPrompter()
					fws := frameworkList()
					selected, err := p.Select("Select compliance framework", fws)
					if err != nil {
						return err
					}
					framework = selected
				}
				if framework == "" {
					return fmt.Errorf("--framework is required")
				}
			}

			report, err := complianceEngine.GenerateReport(context.Background(), compliance.ReportOptions{
				Framework: framework,
			})
			if err != nil {
				return fmt.Errorf("generate report: %w", err)
			}

			if output != "" {
				if err := report.WriteFile(output); err != nil {
					return fmt.Errorf("write report: %w", err)
				}
				fmt.Printf("Report saved to %s\n", output)
			} else {
				fmt.Println(report.RenderText())
			}

			// Push snapshot to server if available
			hostname, _ := os.Hostname()
			snapshot := map[string]any{
				"hostname":     hostname,
				"framework":    report.Framework,
				"score":        report.Score,
				"total":        report.Total,
				"passed":       report.Passed,
				"failed":       report.Failed,
				"not_covered":  report.NotCovered,
			}
			body, _ := json.Marshal(snapshot)
			serverURL := os.Getenv("TRACE_SERVER_URL")
			apiKey := os.Getenv("TRACE_API_KEY")
			if serverURL != "" && apiKey != "" {
				req, _ := http.NewRequest("POST", serverURL+"/api/v1/compliance/snapshot", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+apiKey)
				req.Header.Set("Content-Type", "application/json")
				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}
			return nil
		},
	}
	reportCmd.Flags().StringP("framework", "f", "", "Compliance framework")
	reportCmd.Flags().StringP("output", "o", "", "Output file path")

	assessCmd := &cobra.Command{
		Use:   "assess",
		Short: "Manually assess a compliance control (pass/fail/na)",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			framework, _ := cmdCobra.Flags().GetString("framework")
			control, _ := cmdCobra.Flags().GetString("control")
			status, _ := cmdCobra.Flags().GetString("status")
			notes, _ := cmdCobra.Flags().GetString("notes")

			if framework == "" || control == "" || status == "" {
				return fmt.Errorf("--framework, --control, and --status are required")
			}
			if status != "pass" && status != "fail" && status != "na" {
				return fmt.Errorf("--status must be pass, fail, or na")
			}

			err := complianceEngine.SetManualAssessment(context.Background(), framework, control, status, notes)
			if err != nil {
				return fmt.Errorf("assess: %w", err)
			}
			fmt.Printf("Control %s [%s] marked as %s\n", control, framework, status)
			return nil
		},
	}
	assessCmd.Flags().StringP("framework", "f", "", "Compliance framework")
	assessCmd.Flags().StringP("control", "C", "", "Control ID (e.g. Art.5, 1.2.5)")
	assessCmd.Flags().StringP("status", "s", "", "Assessment: pass, fail, na")
	assessCmd.Flags().StringP("notes", "n", "", "Justification notes")

	evidenceCmd := &cobra.Command{
		Use:   "evidence",
		Short: "Attach evidence to a compliance control",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			framework, _ := cmdCobra.Flags().GetString("framework")
			control, _ := cmdCobra.Flags().GetString("control")
			desc, _ := cmdCobra.Flags().GetString("description")
			file, _ := cmdCobra.Flags().GetString("file")

			if framework == "" || control == "" || desc == "" {
				return fmt.Errorf("--framework, --control, and --description are required")
			}

			err := complianceEngine.AddEvidence(context.Background(), framework, control, desc, file)
			if err != nil {
				return fmt.Errorf("evidence: %w", err)
			}
			fmt.Printf("Evidence added for %s [%s]\n", control, framework)
			return nil
		},
	}
	evidenceCmd.Flags().StringP("framework", "f", "", "Compliance framework")
	evidenceCmd.Flags().StringP("control", "C", "", "Control ID")
	evidenceCmd.Flags().StringP("description", "d", "", "Evidence description")
	evidenceCmd.Flags().String("file", "", "Optional evidence file path")

	listCmd := &cobra.Command{
		Use:   "frameworks",
		Short: "List available compliance frameworks",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			fmt.Println("Available compliance frameworks:")
			for _, fw := range frameworkListFull() {
				fmt.Printf("  %-18s %s\n", fw.id, fw.name)
			}
			return nil
		},
	}

	trendCmd := &cobra.Command{
		Use:   "trend",
		Short: "Show compliance score history over time",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			framework, _ := cmdCobra.Flags().GetString("framework")
			days, _ := cmdCobra.Flags().GetInt("days")

			if framework == "" {
				return fmt.Errorf("--framework is required")
			}

			history, err := complianceEngine.GetHistory(framework, days)
			if err != nil {
				return fmt.Errorf("history: %w", err)
			}

			if len(history) == 0 {
				fmt.Println("No compliance history found. Run 'trace compliance report' first.")
				return nil
			}

			fmt.Printf("\n  Compliance Trend — %s  (last %d days)\n\n", framework, days)
			for _, p := range history {
				score := int(p.Score)
				bar := ""
				for i := 0; i < score/5; i++ {
					bar += "█"
				}
				for i := score / 5; i < 20; i++ {
					bar += "░"
				}
				fmt.Printf("  %s  %3d%%  %s\n", p.Date[:10], score, bar)
			}

			// Show trend direction
			if len(history) >= 2 {
				first, last := history[0].Score, history[len(history)-1].Score
				diff := last - first
				dir := "→ stable"
				if diff > 2 {
					dir = fmt.Sprintf("↑ improving (+%.0f%%)", diff)
				} else if diff < -2 {
					dir = fmt.Sprintf("↓ declining (%.0f%%)", diff)
				}
				fmt.Printf("\n  Trend: %s\n", dir)
			}
			return nil
		},
	}
	trendCmd.Flags().StringP("framework", "f", "", "Compliance framework")
	trendCmd.Flags().Int("days", 30, "Number of days to show")

	cmd.AddCommand(reportCmd, assessCmd, evidenceCmd, listCmd, trendCmd)
	return cmd
}

func frameworkList() []string {
	return []string{
		"pci_dss_v4.0", "pci_dss_v3.2.1", "hipaa", "gdpr",
		"nist_sp_800-53", "iso_27001-2013", "soc_2", "cis_csc_v8",
	}
}

func frameworkListFull() []struct{ id, name string } {
	return []struct{ id, name string }{
		{"pci_dss_v4.0", "PCI DSS v4.0"},
		{"pci_dss_v3.2.1", "PCI DSS v3.2.1"},
		{"hipaa", "HIPAA Security Rule"},
		{"gdpr", "EU GDPR"},
		{"nist_sp_800-53", "NIST SP 800-53 Rev.5"},
		{"iso_27001-2013", "ISO 27001:2013"},
		{"soc_2", "SOC 2"},
		{"cis_csc_v8", "CIS Critical Security Controls v8"},
	}
}
