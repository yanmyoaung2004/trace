package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage EDR agents and view status",
		Long: `View connected EDR agents and their status.
Commands are delegated to 'trace edr' for detailed management.`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			if len(args) > 0 {
				return cmdCobra.Help()
			}
			// Show agent status from server API
			serverURL := app.cfg.Server.HTTPAddr
			if serverURL == "" {
				serverURL = "http://127.0.0.1:8080"
			}
			if !strings.HasPrefix(serverURL, "http") {
				serverURL = "http://" + serverURL
			}
			resp, err := http.Get(serverURL + "/api/v1/edr/agents")
			if err != nil {
				return fmt.Errorf("server unreachable (%s): %w", serverURL, err)
			}
			defer resp.Body.Close()

			var result []map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("parse response: %w", err)
			}

			outf(cmdCobra, "Connected EDR Agents:\n")
			if len(result) == 0 {
				outln(cmdCobra, "  (none registered)")
				return nil
			}
			for _, a := range result {
				id, _ := a["id"].(string)
				hostname, _ := a["hostname"].(string)
				status, _ := a["status"].(string)
				platform, _ := a["platform"].(string)
				version, _ := a["version"].(string)
				if len(id) > 12 {
					id = id[:12]
				}
				outf(cmdCobra, "  %s  %-20s  %-10s  %-8s  %s\n", id, hostname, status, platform, version)
			}
			outln(cmdCobra)
			outln(cmdCobra, "Use 'trace edr view <agent-id>' for details.")
			return nil
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show agent installation status (local)",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			dataDir := app.cfg.DataDir
			if dataDir == "" {
				dataDir = "."
			}
			outf(cmdCobra, "Server data dir: %s\n", dataDir)
			outf(cmdCobra, "Use 'trace agent' to list connected agents.\n")
			outf(cmdCobra, "Use 'trace edr' for full agent management.\n")
			return nil
		},
	})

	return cmd
}
