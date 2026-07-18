package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/innoigniter/edge/internal/agent"
	"github.com/spf13/cobra"
)

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report [investigation-id]",
		Short: "Generate or view investigation report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			ctx := context.Background()

			inv, err := app.invManager.Get(ctx, args[0])
			if err != nil {
				return fmt.Errorf("get investigation: %w", err)
			}

			logFile := filepath.Join(app.cfg.LogDir, inv.ID+".jsonl")
			results := make(map[string]any)
			if f, err := os.Open(logFile); err == nil {
				defer f.Close()
				data, _ := io.ReadAll(f)
				results["log_events"] = string(data)
			}

			reportOutput, err := app.hostAgent.Execute(ctx, agent.Input{
				"action":           "synthesize_report",
				"results":          results,
				"investigation_id": inv.ID,
				"intent":           inv.Intent,
			})
			if err != nil {
				return fmt.Errorf("synthesize report: %w", err)
			}

			report, _ := reportOutput["report"].(string)
			fmt.Println(report)

			outputPath, _ := cmdCobra.Flags().GetString("output")
			if outputPath != "" {
				if err := os.WriteFile(outputPath, []byte(report), 0644); err != nil {
					return fmt.Errorf("write report: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Report saved to %s\n", outputPath)
			}

			return nil
		},
	}

	cmd.Flags().StringP("output", "o", "", "save report to file")
	return cmd
}
