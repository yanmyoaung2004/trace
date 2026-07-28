package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/yanmyoaung2004/trace/internal/agent"
	"github.com/yanmyoaung2004/trace/internal/tui"
	"github.com/spf13/cobra"
)

func newInvestigateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "investigate [query]",
		Short: "Run a security investigation",
		Long: `Run a security investigation using natural language or explicit parameters.

File analysis with human-readable output:
  trace investigate -f /path/to/file.exe

Playbook with params:
  trace investigate --playbook file-analysis --param file=/path/to/file.exe`,
		Args: cobra.ArbitraryArgs,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			playbooks := app.playbooks
			if playbooks == nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			matches := tui.PlaybookCompletions(toComplete, app)
			return matches, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			query := argsToQuery(args)
			playbookName, _ := cmd.Flags().GetString("playbook")
			filePath, _ := cmd.Flags().GetString("file")
			rawParams, _ := cmd.Flags().GetStringToString("param")
			params := make(map[string]any)
			for k, v := range rawParams {
				params[k] = v
			}

			// Handle -f / --file flag for file analysis
			if filePath != "" {
				return runFileAnalysis(ctx, filePath)
			}

			if query == "" && playbookName == "" {
				if tui.IsInteractive() {
					p := tui.NewPrompter()
					q, err := p.Input("What do you want to investigate?", "")
					if err != nil || q == "" {
						return err
					}
					query = strings.TrimSpace(q)

					playbooks := app.ListPlaybooks()
					if len(playbooks) > 0 {
						pbNames := make([]string, len(playbooks))
						for i, pb := range playbooks {
							pbNames[i] = pb.Name
						}
						selected, err := p.Select("Select a playbook", pbNames)
						if err != nil {
							return err
						}
						if selected != "" {
							playbookName = selected
						}
					}
				}
				if query == "" && playbookName == "" {
					return fmt.Errorf("provide a query or --playbook flag")
				}
			}

			if playbookName == "" && query != "" {
				intentOutput, err := app.dispatchAgent.Execute(ctx, agent.Input{
					"action": "classify_intent",
					"query":  query,
				})
				if err != nil {
					return fmt.Errorf("classify intent: %w", err)
				}
				playbookName, _ = intentOutput["playbook"].(string)

				planInput := agent.Input{
					"action":   "plan_investigation",
					"intent":   query,
					"playbook": playbookName,
				}
				planOutput, err := app.dispatchAgent.Execute(ctx, planInput)
				if err == nil {
					if p, ok := planOutput["parameters"].(map[string]any); ok {
						for k, v := range p {
							if _, set := params[k]; !set {
								if vs, ok := v.(string); ok {
									params[k] = vs
								}
							}
						}
					}
				}
			}

			for k, v := range extractParamsFromQuery(query) {
				if _, set := params[k]; !set {
					params[k] = v
				}
			}
			params = normalizeParams(params)

			pb := app.playbooks.Get(playbookName)
			if pb == nil {
				return fmt.Errorf("playbook %q not found", playbookName)
			}

			outf(cmd, "Running playbook: %s (%s)\n", pb.Name, pb.Description)

			inv, err := app.invManager.Create(ctx, query, playbookName)
			if err != nil {
				return fmt.Errorf("create investigation: %w", err)
			}
			outf(cmd, "Investigation ID: %s\n", inv.ID)

			results, err := app.executor.Execute(ctx, inv, pb, params)
			if err != nil {
				return fmt.Errorf("execute playbook: %w", err)
			}

			reportOutput, err := app.dispatchAgent.Execute(ctx, agent.Input{
				"action":          "synthesize_report",
				"results":         results,
				"investigation_id": inv.ID,
				"intent":           query,
			})
			if err != nil {
				return fmt.Errorf("synthesize report: %w", err)
			}

			report, _ := reportOutput["report"].(string)
			outln(cmd, report)

			return nil
		},
	}

	cmd.Flags().StringP("playbook", "p", "", "playbook name to run")
	cmd.Flags().StringP("file", "f", "", "Analyze a file (runs PE/hash analysis)")
	cmd.Flags().StringToString("param", nil, "parameters for the playbook (key=value)")
	cmd.RegisterFlagCompletionFunc("playbook", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return tui.PlaybookCompletions(toComplete, app), cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

func runFileAnalysis(ctx context.Context, path string) error {
	// Stat the file first
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Analyzing: %s (%d bytes)\n", path, info.Size())
	fmt.Fprintln(os.Stderr)

	// Run PE analysis through the plugin registry
	siftPlugin := app.registry.Get("sift")
	if siftPlugin == nil {
		return fmt.Errorf("sift plugin not available")
	}

	peResult, err := siftPlugin.Execute(ctx, agent.Input{
		"action": "pe_analyze",
		"path":   path,
	})
	if err != nil {
		return fmt.Errorf("pe analyze: %w", err)
	}

	isPE, _ := peResult["is_pe"].(bool)
	fmt.Fprintf(os.Stderr, "File type:  ")
	if isPE {
		fmt.Fprintln(os.Stderr, "PE (Portable Executable)")
	} else {
		fmt.Fprintln(os.Stderr, "Not a PE file (generic analysis)")
	}

	if md5 := toStr(peResult["md5"]); md5 != "" {
		fmt.Fprintf(os.Stderr, "MD5:        %s\n", md5)
	}
	if sha256 := toStr(peResult["sha256"]); sha256 != "" {
		fmt.Fprintf(os.Stderr, "SHA256:     %s\n", sha256)
	}
	if sz := toFloat(peResult["file_size"]); sz > 0 {
		fmt.Fprintf(os.Stderr, "Size:       %d bytes\n", int64(sz))
	}

	if isPE {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "--- PE Details ---")

		if ss := toStr(peResult["subsystem"]); ss != "" {
			fmt.Fprintf(os.Stderr, "Subsystem:  %s\n", ss)
		}
		if ct := toStr(peResult["compile_timestamp"]); ct != "" {
			fmt.Fprintf(os.Stderr, "Compiled:   %s\n", ct)
		}
		if ep := toStr(peResult["entry_point"]); ep != "" {
			fmt.Fprintf(os.Stderr, "Entry:      %s\n", ep)
		}
		if ent := toFloat(peResult["entropy"]); ent > 0 {
			fmt.Fprintf(os.Stderr, "Entropy:    %.2f", ent)
			if hi, _ := peResult["high_entropy"].(bool); hi {
				fmt.Fprintf(os.Stderr, " (HIGH — possible packed/encrypted)")
			}
			fmt.Fprintln(os.Stderr)
		}

		// Sections
		if sections, ok := peResult["sections"].([]any); ok && len(sections) > 0 {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "Sections:")
			for _, s := range sections {
				if m, ok := s.(map[string]any); ok {
					name, _ := m["name"].(string)
					rawSize, _ := m["raw_size"].(float64)
					entropy, _ := m["entropy"].(float64)
					flags, _ := m["flags"].(string)
					fmt.Fprintf(os.Stderr, "  %-10s  %8d bytes  entropy=%.2f  [%s]\n", name, int(rawSize), entropy, flags)
				}
			}
		}

		// Imports
		if imports, ok := peResult["imports"].([]any); ok && len(imports) > 0 {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "Imports (%d DLLs):\n", len(imports))
			for _, imp := range imports {
				fmt.Fprintf(os.Stderr, "  %s\n", toStr(imp))
			}
		}

		// Suspicious indicators
		if susp, ok := peResult["suspicious"].([]any); ok && len(susp) > 0 {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "Suspicious Indicators:")
			for _, s := range susp {
				fmt.Fprintf(os.Stderr, "  ⚠ %s\n", toStr(s))
			}
		}
	}

	// Hash lookup
	hash := toStr(peResult["sha256"])
	if hash == "" {
		hash = toStr(peResult["md5"])
	}
	if hash != "" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "--- Hash Lookup ---\n")

		repResult, err := siftPlugin.Execute(ctx, agent.Input{
			"action": "hash_lookup",
			"hash":   hash,
		})
		if err == nil {
			if rep, _ := repResult["reputation"].(string); rep != "" {
				fmt.Fprintf(os.Stderr, "Reputation: %s\n", rep)
			}
			if src, _ := repResult["source"].(string); src != "" {
				fmt.Fprintf(os.Stderr, "Source:     %s\n", src)
			}
		}
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Run 'trace investigation start' or 'trace case create' to build a case.")
	return nil
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toFloat(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func argsToQuery(args []string) string {
	if len(args) == 0 {
		return ""
	}
	q := ""
	for i, a := range args {
		if i > 0 {
			q += " "
		}
		q += a
	}
	return q
}
