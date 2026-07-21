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
Examples:
  trace investigate "check hash d41d8cd98f00b204e9800998ecf8427e"
  trace investigate --playbook hash-lookup --param hash=<sha256>
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
			rawParams, _ := cmd.Flags().GetStringToString("param")
			params := make(map[string]any)
			for k, v := range rawParams {
				params[k] = v
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

			fmt.Fprintf(os.Stderr, "Running playbook: %s (%s)\n", pb.Name, pb.Description)

			inv, err := app.invManager.Create(ctx, query, playbookName)
			if err != nil {
				return fmt.Errorf("create investigation: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Investigation ID: %s\n", inv.ID)

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
			fmt.Println(report)

			return nil
		},
	}

	cmd.Flags().StringP("playbook", "p", "", "playbook name to run")
	cmd.Flags().StringToString("param", nil, "parameters for the playbook (key=value)")
	cmd.RegisterFlagCompletionFunc("playbook", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return tui.PlaybookCompletions(toComplete, app), cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
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
