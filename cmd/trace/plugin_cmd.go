package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func pluginDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trace", "plugins")
}

func newPluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage external agent plugins",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List installed plugins and their capabilities",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			agents := app.registry.List()
			if len(agents) == 0 {
				fmt.Println("No agents registered.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Agent\tActions")
			for _, a := range agents {
				caps := a.Capabilities()
				actions := ""
				for i, c := range caps {
					if i > 0 {
						actions += ", "
					}
					actions += c.Action
				}
				fmt.Fprintf(w, "%s\t%s\n", a.Name(), actions)
			}
			w.Flush()

			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "install [url]",
		Short: "Download and install a plugin binary",
		Long: `Download a .so plugin binary from a URL and install it.
The plugin must export a "Plugin" symbol implementing agent.AgentPlugin.

Example:
  trace plugin install https://plugins.trace.sh/v1/plugins/exporter.so`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			url := args[0]
			dir := pluginDir()
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("create plugin dir: %w", err)
			}

			name := filepath.Base(url)
			dest := filepath.Join(dir, name)

			fmt.Fprintf(os.Stderr, "Downloading %s...\n", url)

			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Get(url)
			if err != nil {
				return fmt.Errorf("download plugin: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("download failed: %s", resp.Status)
			}

			f, err := os.Create(dest)
			if err != nil {
				return fmt.Errorf("create plugin file: %w", err)
			}
			defer f.Close()

			written, err := io.Copy(f, resp.Body)
			if err != nil {
				os.Remove(dest)
				return fmt.Errorf("write plugin: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Installed %s (%d bytes) to %s\n", name, written, dest)
			fmt.Printf("Plugin %q installed. Restart serve to load it.\n", name)

			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "remove [name]",
		Short: "Remove an installed plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			name := args[0]
			if !strings.HasSuffix(name, ".so") {
				name += ".so"
			}
			path := filepath.Join(pluginDir(), name)
			if err := os.Remove(path); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("plugin %q not found", name)
				}
				return fmt.Errorf("remove plugin: %w", err)
			}
			fmt.Printf("Plugin %q removed.\n", name)
			return nil
		},
	})

	return cmd
}

func init() {
	_ = context.Background()
}
