package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/admin"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
	"github.com/yanmyoaung2004/trace/internal/storage/snapshot"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

func newTSECmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tse",
		Short: "Trace Storage Engine management",
		Long:  `Manage the Trace Storage Engine: view status, trigger flushes, inspect files.`,
	}

	var storagePath string

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show TSE status",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			sp, _ := cmdCobra.Flags().GetString("storage-path")
			if sp != "" {
				return tseStatusStandalone(sp)
			}
			if app.tse == nil {
				return fmt.Errorf("TSE not enabled (use --tse flag on serve, or --storage-path)")
			}
			s, err := admin.Status(context.Background(), app.tse.Manifest, app.tse.Flusher)
			if err != nil {
				return err
			}
			fmt.Print(s)
			return nil
		},
	}
	statusCmd.Flags().StringVar(&storagePath, "storage-path", "", "TSE data directory (standalone, no server needed)")

	flushCmd := &cobra.Command{
		Use:   "flush",
		Short: "Trigger an immediate flush cycle",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			if app.tse == nil {
				return fmt.Errorf("TSE not enabled (use --tse flag on serve)")
			}
			return admin.FlushNow(context.Background(), app.tse.Flusher)
		},
	}

	inspectCmd := &cobra.Command{
		Use:   "inspect",
		Short: "List recent Parquet files in the manifest",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			sp, _ := cmdCobra.Flags().GetString("storage-path")
			if sp != "" {
				return tseInspectStandalone(sp)
			}
			if app.tse == nil {
				return fmt.Errorf("TSE not enabled (use --tse flag on serve, or --storage-path)")
			}
			s, err := admin.Inspect(context.Background(), app.tse.Manifest, 50)
			if err != nil {
				return err
			}
			fmt.Print(s)
			return nil
		},
	}
	inspectCmd.Flags().StringVar(&storagePath, "storage-path", "", "TSE data directory (standalone, no server needed)")

	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Create a TSE snapshot",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			sp, _ := cmdCobra.Flags().GetString("storage-path")
			if sp == "" {
				return fmt.Errorf("--storage-path is required")
			}
			if app.tse == nil {
				return fmt.Errorf("TSE not enabled")
			}
			output, _ := cmdCobra.Flags().GetString("output")
			if output == "" {
				output = fmt.Sprintf("tse-snapshot-%s.tar.gz", time.Now().Format("20060102-150405"))
			}
			return snapshot.Create(context.Background(), output, sp, app.tse.Flusher, app.tse.Manifest)
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

func tseStatusStandalone(storagePath string) error {
	ctx := context.Background()
	m, err := manifest.NewManifest(filepath.Join(storagePath, "manifest.db"))
	if err != nil {
		return fmt.Errorf("open manifest: %w", err)
	}
	defer m.Close()

	wm, err := m.Watermark(ctx)
	if err != nil {
		return fmt.Errorf("watermark: %w", err)
	}

	files, _ := m.FilesFor(ctx, "", 0, 0, "committed")
	hotEventCount := 0
	hotTables := 0
	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(storagePath, "hot.db"))
	if err == nil {
		result, qErr := hot.Query(ctx, storage.Query{Limit: 1000000})
		if qErr == nil {
			hotEventCount = len(result.Events)
		}
		tables, _ := hot.LiveTables(ctx)
		hotTables = len(tables)
		hot.Close()
	}

	fmt.Printf(`TSE Status:
  Storage path: %s
  Watermark:    %s
  Hot events:   %d
  Hot tables:   %d
  Cold files:   %d
  Parquet files:
`, storagePath, wm.LastID, hotEventCount, hotTables, len(files))
	for _, f := range files {
		fmt.Printf("    %s  (level=%d, tenant=%s)\n", f.Path, f.Level, f.TenantID)
	}
	if len(files) == 0 {
		fmt.Println("    (none)")
	}
	return nil
}

func tseInspectStandalone(storagePath string) error {
	m, err := manifest.NewManifest(filepath.Join(storagePath, "manifest.db"))
	if err != nil {
		return fmt.Errorf("open manifest: %w", err)
	}
	defer m.Close()

	s, err := admin.Inspect(context.Background(), m, 50)
	if err != nil {
		return err
	}
	fmt.Print(s)
	return nil
}
