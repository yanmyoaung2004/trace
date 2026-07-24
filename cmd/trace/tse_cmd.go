package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/yanmyoaung2004/trace/internal/storage/admin"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
	"github.com/yanmyoaung2004/trace/internal/storage/snapshot"
)

func newTSECmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tse",
		Short: "Trace Storage Engine management",
		Long:  `Manage the Trace Storage Engine: view status, trigger flushes, inspect files.`,
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show TSE status",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			if app.tse == nil {
				return fmt.Errorf("TSE not enabled (use --tse flag on serve)")
			}
			s, err := admin.Status(context.Background(), app.tse.Manifest, app.tse.Flusher)
			if err != nil {
				return err
			}
			fmt.Print(s)
			return nil
		},
	}

	flushCmd := &cobra.Command{
		Use:   "flush",
		Short: "Trigger an immediate flush cycle",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			if app.tse == nil {
				return fmt.Errorf("TSE not enabled")
			}
			return admin.FlushNow(context.Background(), app.tse.Flusher)
		},
	}

	inspectCmd := &cobra.Command{
		Use:   "inspect",
		Short: "List recent Parquet files in the manifest",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			if app.tse == nil {
				return fmt.Errorf("TSE not enabled")
			}
			s, err := admin.Inspect(context.Background(), app.tse.Manifest, 50)
			if err != nil {
				return err
			}
			fmt.Print(s)
			return nil
		},
	}

	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Create a TSE snapshot",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			if app.tse == nil {
				return fmt.Errorf("TSE not enabled")
			}
			output, _ := cmdCobra.Flags().GetString("output")
			if output == "" {
				output = fmt.Sprintf("tse-snapshot-%s.tar.gz", time.Now().Format("20060102-150405"))
			}
			storagePath, _ := cmdCobra.Flags().GetString("storage-path")
			if storagePath == "" {
				return fmt.Errorf("--storage-path is required")
			}
			return snapshot.Create(context.Background(), output, storagePath, app.tse.Flusher, app.tse.Manifest)
		},
	}
	snapshotCmd.Flags().StringP("output", "o", "", "Output file path")
	snapshotCmd.Flags().String("storage-path", "", "TSE storage path (required)")

	metricsCmd := &cobra.Command{
		Use:   "metrics",
		Short: "Show TSE metrics",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			meta := metrics.Global.Snapshot()
			for k, v := range meta {
				fmt.Printf("  %-25s %v\n", k, v)
			}
			return nil
		},
	}

	cmd.AddCommand(statusCmd, flushCmd, inspectCmd, snapshotCmd, metricsCmd)
	return cmd
}
