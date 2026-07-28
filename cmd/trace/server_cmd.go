package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/yanmyoaung2004/trace/internal/server"
	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
	"github.com/spf13/cobra"
)

func newServerCmd() *cobra.Command {
	var tseStoragePath string

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start in central server mode",
		Long: `Start Trace in central server mode with web dashboard and sync API.
Edge nodes connect to this server to push investigations and receive cross-node correlation.

Use --tse-storage-path to enable long-term storage of EDR agent events in TSE.`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			log.SetOutput(os.Stderr)
			if err := app.initialize(cmdCobra.Flag("config").Value.String()); err != nil {
				return err
			}

			httpAddr, _ := cmdCobra.Flags().GetString("http-addr")
			if httpAddr != "" {
				app.cfg.Server.HTTPAddr = httpAddr
			}
			if cert, _ := cmdCobra.Flags().GetString("tls-cert"); cert != "" {
				app.cfg.Server.TLS.CertFile = cert
				app.cfg.Server.TLS.Enabled = true
			}
			if key, _ := cmdCobra.Flags().GetString("tls-key"); key != "" {
				app.cfg.Server.TLS.KeyFile = key
			}
			app.cfg.Server.Enabled = true

			fmt.Printf("Trace v%s — Server Mode\n", Version)

			var tseWriter server.EventWriter
			if tseStoragePath != "" {
				hot, err := sqlite.NewSQLiteHotStore(tseStoragePath)
				if err != nil {
					return fmt.Errorf("init TSE hot store: %w", err)
				}
				defer hot.Close()
				tseWriter = &tseHotStoreAdapter{hot: hot}
				log.Printf("[server] TSE hot store: %s", tseStoragePath)
			}

			return server.RunServer(app.cfg, app.database, app.invManager, tseWriter)
		},
	}

	cmd.Flags().String("http-addr", ":8080", "HTTP API + dashboard address")
	cmd.Flags().String("tls-cert", "", "TLS certificate file path")
	cmd.Flags().String("tls-key", "", "TLS private key file path")
	cmd.Flags().StringVar(&tseStoragePath, "tse-storage-path", "", "TSE storage path (enables long-term event storage)")
	return cmd
}

type tseHotStoreAdapter struct {
	hot *sqlite.SQLiteHotStore
}

func (a *tseHotStoreAdapter) WriteEvents(ctx context.Context, events []*storage.Event) error {
	return a.hot.WriteBatch(ctx, events)
}
