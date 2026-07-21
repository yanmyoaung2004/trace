package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/yanmyoaung2004/trace/internal/compliance"
	"github.com/yanmyoaung2004/trace/internal/plugins/sca"
	"github.com/yanmyoaung2004/trace/internal/tui"
	"github.com/spf13/cobra"
)

func newComplianceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Run compliance scans and generate reports (GDPR, HIPAA, PCI, NIST, ISO 27001, SOC 2)",
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
  trace compliance report --framework hipaa -o report.html
  trace compliance report --framework gdpr -o gdpr-report.md
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
			format, _ := cmdCobra.Flags().GetString("format")

			if framework == "" {
				if tui.IsInteractive() {
					p := tui.NewPrompter()
					fws := []string{"pci_dss_v4.0", "pci_dss_v3.2.1", "hipaa", "gdpr", "nist_sp_800-53", "iso_27001-2013", "soc_2", "cis_csc_v8"}
					selected, err := p.Select("Select compliance framework", fws)
					if err != nil {
						return err
					}
					framework = selected
				}
				if framework == "" {
					return fmt.Errorf("--framework is required (pci_dss_v4.0, hipaa, gdpr, nist_sp_800-53, iso_27001-2013, soc_2)")
				}
			}

			if format == "" {
				if strings.HasSuffix(output, ".html") {
					format = "html"
				} else if strings.HasSuffix(output, ".json") {
					format = "json"
				} else {
					format = "markdown"
				}
			}

			engine := compliance.NewEngine(sca.New())
			report, err := engine.GenerateReport(context.Background(), compliance.ReportOptions{
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
			return nil
		},
	}
	reportCmd.Flags().StringP("framework", "f", "", "Compliance framework (pci_dss_v4.0, hipaa, gdpr, nist_sp_800-53, iso_27001-2013, soc_2)")
	reportCmd.Flags().StringP("output", "o", "", "Output file path")
	reportCmd.Flags().String("format", "", "Output format (markdown, html, json, txt)")

	listCmd := &cobra.Command{
		Use:   "frameworks",
		Short: "List available compliance frameworks",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			fmt.Println("Available compliance frameworks:")
			for _, fw := range []struct {
				id, name string
			}{
				{"pci_dss_v4.0", "PCI DSS v4.0"},
				{"pci_dss_v3.2.1", "PCI DSS v3.2.1"},
				{"hipaa", "HIPAA Security Rule"},
				{"gdpr", "EU GDPR"},
				{"nist_sp_800-53", "NIST SP 800-53 Rev.5"},
				{"iso_27001-2013", "ISO 27001:2013"},
				{"soc_2", "SOC 2"},
				{"cis_csc_v8", "CIS Critical Security Controls v8"},
			} {
				fmt.Printf("  %-16s %s\n", fw.id, fw.name)
			}
			return nil
		},
	}

	cmd.AddCommand(reportCmd, listCmd)
	return cmd
}
