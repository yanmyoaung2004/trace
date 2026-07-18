package main

import (
	"context"
	"encoding/json"
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

var pluginRegistryBase = "https://github.com/yanmyoaung2004/trace/releases/latest/download/plugins"

func resolvePluginURL(input string) string {
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		return input
	}
	name := input
	if !strings.HasSuffix(name, ".so") {
		name += ".so"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(pluginRegistryBase + "/index.json")
	if err == nil {
		defer resp.Body.Close()
		var entries []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		}
		if json.NewDecoder(resp.Body).Decode(&entries) == nil {
			for _, e := range entries {
				if e.Name == input {
					return e.URL
				}
			}
		}
	}
	return pluginRegistryBase + "/" + name
}

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
		Use:   "search [query]",
		Short: "Search available plugins in the registry",
		Long: `Search for plugins in the Trace plugin registry.
If no query is given, lists all available plugins.

Examples:
  trace plugin search
  trace plugin search siem`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get("https://github.com/yanmyoaung2004/trace/releases/latest/download/plugins/index.json")
			if err != nil {
				fmt.Fprintln(os.Stderr, "Warning: cannot reach plugin registry (offline?)")
				return nil
			}
			defer resp.Body.Close()

			var entries []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			}
			json.NewDecoder(resp.Body).Decode(&entries)

			query := ""
			if len(args) > 0 {
				query = strings.ToLower(args[0])
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "Name\tDescription")
			for _, e := range entries {
				if query != "" && !strings.Contains(strings.ToLower(e.Name), query) && !strings.Contains(strings.ToLower(e.Description), query) {
					continue
				}
				fmt.Fprintf(w, "%s\t%s\n", e.Name, e.Description)
			}
			w.Flush()
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "install [name-or-url]",
		Short: "Download and install a plugin",
		Long: `Install a plugin by name or URL.
If a name is given, looks it up in the plugin registry (falls back to direct download).
If a URL is given, downloads directly.

Examples:
  trace plugin install exporter
  trace plugin install https://example.com/plugins/my-plugin.so`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			url := resolvePluginURL(args[0])
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
