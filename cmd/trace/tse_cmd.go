package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/yanmyoaung2004/trace/internal/config"
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
				return tseStatusStandalone(cmdCobra, sp)
			}
			if app.tse == nil {
				return fmt.Errorf("TSE not enabled (use --tse flag on serve, or --storage-path)")
			}
			s, err := admin.Status(context.Background(), app.tse.Manifest, app.tse.Flusher)
			if err != nil {
				return err
			}
			outstr(cmdCobra, s)
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
			tok, _ := cmdCobra.Flags().GetString("admin-token")
			if tok != "" && tok != app.cfg.TSE.AdminToken {
				return fmt.Errorf("invalid admin token")
			}
			return admin.FlushNow(context.Background(), app.tse.Flusher)
		},
	}
	flushCmd.Flags().String("admin-token", "", "admin token for destructive operations")

	inspectCmd := &cobra.Command{
		Use:   "inspect",
		Short: "List recent Parquet files in the manifest",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			sp, _ := cmdCobra.Flags().GetString("storage-path")
			if sp != "" {
				return tseInspectStandalone(cmdCobra, sp)
			}
			if app.tse == nil {
				return fmt.Errorf("TSE not enabled (use --tse flag on serve, or --storage-path)")
			}
			s, err := admin.Inspect(context.Background(), app.tse.Manifest, 50)
			if err != nil {
				return err
			}
			outstr(cmdCobra, s)
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
			tok, _ := cmdCobra.Flags().GetString("admin-token")
			if tok != "" && tok != app.cfg.TSE.AdminToken {
				return fmt.Errorf("invalid admin token")
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
	snapshotCmd.Flags().String("admin-token", "", "admin token for destructive operations")

	metricsCmd := &cobra.Command{
		Use:   "metrics",
		Short: "Show TSE metrics",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			meta := metrics.Global.Snapshot()
			for k, v := range meta {
				outf(cmdCobra, "  %-25s %v\n", k, v)
			}
			return nil
		},
	}

	configCmd := &cobra.Command{
		Use:   "config",
		Short: "View or modify TSE configuration",
	}
	configShowCmd := &cobra.Command{
		Use:   "show",
		Short: "Show current TSE config",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			home, _ := os.UserHomeDir()
			cfg, err := config.Load(filepath.Join(home, ".trace", "config.json"))
			if err != nil {
				return err
			}
			data, _ := json.MarshalIndent(cfg.TSE, "", "  ")
			outln(cmdCobra, string(data))
			return nil
		},
	}
	configSetCmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a TSE config value (e.g. retention.days 90)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			home, _ := os.UserHomeDir()
			path := filepath.Join(home, ".trace", "config.json")
			cfg, err := config.Load(path)
			if err != nil {
				return err
			}
			key, val := args[0], args[1]
			switch key {
			case "storage_path":
				cfg.TSE.StoragePath = val
			case "compression":
				cfg.TSE.Compression = val
			case "compression_level":
				fmt.Sscanf(val, "%d", &cfg.TSE.CompressionLevel)
			case "row_group_size":
				fmt.Sscanf(val, "%d", &cfg.TSE.RowGroupSize)
			case "hot_window":
				cfg.TSE.HotWindow = val
			case "flush_interval":
				cfg.TSE.FlushInterval = val
			case "cold_ttl", "retention.days":
				cfg.TSE.ColdTTL = val
			case "admin_token":
				cfg.TSE.AdminToken = val
			case "s3_bucket":
				cfg.TSE.S3Bucket = val
			case "s3_endpoint":
				cfg.TSE.S3Endpoint = val
			case "s3_region":
				cfg.TSE.S3Region = val
			default:
				return fmt.Errorf("unknown config key: %s (valid: storage_path, compression, compression_level, row_group_size, hot_window, flush_interval, cold_ttl, retention.days)", key)
			}
			if err := config.Save(path, cfg); err != nil {
				return err
			}
			fmt.Printf("tse.%s = %s\n", key, val)
			return nil
		},
	}
	configCmd.AddCommand(configShowCmd, configSetCmd)
	cmd.AddCommand(statusCmd, flushCmd, inspectCmd, snapshotCmd, metricsCmd, configCmd)
	return cmd
}

func tseStatusStandalone(cmd *cobra.Command, storagePath string) error {
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

	outf(cmd, `TSE Status:
  Storage path: %s
  Watermark:    %s
  Hot events:   %d
  Hot tables:   %d
  Cold files:   %d
  Parquet files:
`, storagePath, wm.LastID, hotEventCount, hotTables, len(files))
	for _, f := range files {
		outf(cmd, "    %s  (level=%d, tenant=%s)\n", f.Path, f.Level, f.TenantID)
	}
	if len(files) == 0 {
		outln(cmd, "    (none)")
	}
	return nil
}

func tseInspectStandalone(cmd *cobra.Command, storagePath string) error {
	m, err := manifest.NewManifest(filepath.Join(storagePath, "manifest.db"))
	if err != nil {
		return fmt.Errorf("open manifest: %w", err)
	}
	defer m.Close()

	s, err := admin.Inspect(context.Background(), m, 50)
	if err != nil {
		return err
	}
	outstr(cmd, s)
	return nil
}
