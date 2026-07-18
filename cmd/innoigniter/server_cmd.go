package main

import (
	"fmt"

	"github.com/innoigniter/edge/internal/server"
	"github.com/spf13/cobra"
)

func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start in central server mode",
		Long: `Start InnoIgniterAI in central server mode with web dashboard and sync API.
Edge nodes connect to this server to push investigations and receive cross-node correlation.

Examples:
  innoigniter server
  innoigniter server --http-addr :9090
  innoigniter server --config server-config.json`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
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

			fmt.Printf("InnoIgniterAI v%s — Server Mode\n", Version)
			return server.RunServer(app.cfg, app.database, app.invManager)
		},
	}

	cmd.Flags().String("http-addr", ":8080", "HTTP API + dashboard address")
	cmd.Flags().String("tls-cert", "", "TLS certificate file path")
	cmd.Flags().String("tls-key", "", "TLS private key file path")
	return cmd
}
