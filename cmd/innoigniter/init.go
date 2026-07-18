package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func prompt(reader *bufio.Reader, label string) string {
	fmt.Print(label)
	val, _ := reader.ReadString('\n')
	return strings.TrimSpace(val)
}

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "First-run setup wizard",
		Long: `Interactive setup that creates ~/.innoigniter/config.json with your preferences.
You can skip any step — the tool works without external API keys.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			home, _ := os.UserHomeDir()
			base := filepath.Join(home, ".innoigniter")
			cfgPath := filepath.Join(base, "config.json")

			if _, err := os.Stat(cfgPath); err == nil {
				resp := prompt(bufio.NewReader(os.Stdin), "Config already exists. Overwrite? [y/N] ")
				if strings.ToLower(resp) != "y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			os.MkdirAll(base, 0755)
			reader := bufio.NewReader(os.Stdin)

			fmt.Println("InnoIgniterAI Setup")
			fmt.Println(strings.Repeat("=", 40))
			fmt.Println("Press Enter to skip any option.")

			cfg := map[string]any{
				"db_path":   filepath.Join(base, "innoigniter.db"),
				"data_dir":  filepath.Join(base, "data"),
				"log_dir":   filepath.Join(base, "logs"),
				"playbook":  filepath.Join(base, "playbooks"),
				"intel_dir": filepath.Join(base, "intel"),
			}

			if vtKey := prompt(reader, "\nVirusTotal API key (optional): "); vtKey != "" {
				cfg["vt_api_key"] = vtKey
			}

			if llmURL := prompt(reader, "LLM provider URL (optional, e.g. https://api.openai.com/v1/chat/completions): "); llmURL != "" {
				cfg["llm_url"] = llmURL
				if llmKey := prompt(reader, "LLM API key: "); llmKey != "" {
					cfg["llm_api_key"] = llmKey
				}
				cfg["llm_provider"] = "openai"
			}

			if wsKey := prompt(reader, "Web search API key (optional): "); wsKey != "" {
				cfg["web_search_key"] = wsKey
			}

			if siemResp := prompt(reader, "Enable SIEM log monitoring? [y/N]: "); strings.ToLower(siemResp) == "y" {
				cfg["siem"] = map[string]any{
					"enabled":     true,
					"log_dir":     filepath.Join(base, "logs"),
					"syslog_addr": ":514",
				}
			}

			if telResp := prompt(reader, "Enable telemetry (version, OS, counts only)? [y/N]: "); strings.ToLower(telResp) == "y" {
				cfg["telemetry"] = map[string]any{"enabled": true}
			}

			data, _ := json.MarshalIndent(cfg, "", "  ")
			if err := os.WriteFile(cfgPath, data, 0644); err != nil {
				return fmt.Errorf("write config: %w", err)
			}

			fmt.Printf("\nConfig written to %s\n", cfgPath)
			fmt.Println("Run 'innoigniter serve' to start or 'innoigniter investigate' for a quick check.")
			return nil
		},
	}
}
