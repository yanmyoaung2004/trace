package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
		Long: `Interactive setup that creates ~/.trace/config.json with your preferences.
You can skip any step — the tool works without external API keys.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			home, _ := os.UserHomeDir()
			base := filepath.Join(home, ".trace")
			cfgPath := filepath.Join(base, "config.json")

			if _, err := os.Stat(cfgPath); err == nil {
				resp := prompt(bufio.NewReader(os.Stdin), "Config already exists. Overwrite? [y/N] ")
				if strings.ToLower(resp) != "y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			os.MkdirAll(base, 0755)

			repoPb := filepath.Join(filepath.Dir(os.Args[0]), "playbooks")
			if _, err := os.Stat(repoPb); err == nil {
				fmt.Printf("Found playbook library at %s (linked)\n", repoPb)
			}

			reader := bufio.NewReader(os.Stdin)

			fmt.Println("Trace Setup")
			fmt.Println(strings.Repeat("=", 40))
			fmt.Println("Press Enter to skip any option.")

			cfg := map[string]any{
				"db_path":   filepath.Join(base, "trace.db"),
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
			if llmModel := prompt(reader, "LLM model (e.g. gpt-4, claude-3-haiku, llama3) [gpt-4]: "); llmModel != "" {
				cfg["llm_model"] = llmModel
			}
				cfg["llm_provider"] = "openai"
			}

		if wsKey := prompt(reader, "Firecrawl API key (web search, optional): "); wsKey != "" {
			cfg["web_search_key"] = wsKey
		}

		if abuseKey := prompt(reader, "AbuseIPDB API key (free, for IP reputation): "); abuseKey != "" {
			cfg["abuseipdb_key"] = abuseKey
		}

		if otxKey := prompt(reader, "AlienVault OTX API key (free, for threat intel): "); otxKey != "" {
			cfg["otx_api_key"] = otxKey
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

			fmt.Println("\n-- Notifications (optional) --")
			if slackURL := prompt(reader, "Slack webhook URL (e.g. https://hooks.slack.com/...): "); slackURL != "" {
				cfg["slack_webhook_url"] = slackURL
			}
			if discordURL := prompt(reader, "Discord webhook URL (e.g. https://discord.com/api/webhooks/...): "); discordURL != "" {
				cfg["discord_webhook_url"] = discordURL
			}
			if tgBot := prompt(reader, "Telegram bot token (from @BotFather): "); tgBot != "" {
				cfg["telegram_bot_token"] = tgBot
				if tgChat := prompt(reader, "Telegram chat ID (from @userinfobot): "); tgChat != "" {
					cfg["telegram_chat_id"] = tgChat
				}
			}

			data, _ := json.MarshalIndent(cfg, "", "  ")
			if err := os.WriteFile(cfgPath, data, 0644); err != nil {
				return fmt.Errorf("write config: %w", err)
			}

			fmt.Printf("\nConfig written to %s\n", cfgPath)

			if resp := prompt(reader, "\nAdd trace to your PATH so you can run it from anywhere? [y/N]: "); strings.ToLower(resp) == "y" {
				binDir, _ := filepath.Split(os.Args[0])
				absDir, _ := filepath.Abs(binDir)

				if runtime.GOOS == "windows" {
					psCmd := fmt.Sprintf(`$dir = '%s'; $path = [Environment]::GetEnvironmentVariable('PATH', 'User'); if ($path -notlike '*'+$dir+'*') { [Environment]::SetEnvironmentVariable('PATH', $dir+';'+$path, 'User'); Write-Output 'Added to PATH. Restart your terminal to use just: trace' } else { Write-Output 'Already in PATH.' }`, absDir)
					os.WriteFile(filepath.Join(os.TempDir(), "add-trace-path.ps1"), []byte(psCmd), 0644)
					exec, _ := os.Executable()
					if strings.HasSuffix(strings.ToLower(exec), ".exe") {
						fmt.Printf("Run this in an admin PowerShell to add trace to PATH:\n  [Environment]::SetEnvironmentVariable('PATH', '%s;'+[Environment]::GetEnvironmentVariable('PATH','User'), 'User')\n\n", absDir)
						fmt.Printf("Or manually add %s to your PATH.\n", absDir)
					}
				} else {
					rcPath := filepath.Join(os.Getenv("HOME"), ".bashrc")
					if _, err := os.Stat(rcPath); os.IsNotExist(err) {
						rcPath = filepath.Join(os.Getenv("HOME"), ".zshrc")
					}
					line := fmt.Sprintf("\nexport PATH=\"%s:$PATH\"\n", absDir)
					f, _ := os.OpenFile(rcPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if f != nil {
						f.WriteString(line)
						f.Close()
						fmt.Printf("Added to %s. Run 'source %s' or restart your shell.\n", rcPath, rcPath)
					}
				}
			}

			fmt.Println("\nDone! Start investigating:")
			fmt.Println("  trace serve          # start the daemon")
			fmt.Println("  trace investigate    # run an investigation")
			return nil
		},
	}
}
