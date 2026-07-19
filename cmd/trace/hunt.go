package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/yanmyoaung2004/trace/internal/tui"
	"github.com/spf13/cobra"
)

func huntNameCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	hs, err := app.huntManager.List(context.Background(), "")
	if err != nil || len(hs) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var matches []string
	for _, h := range hs {
		if strings.HasPrefix(h.Name, toComplete) {
			matches = append(matches, h.Name)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

func newHuntCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hunt",
		Short: "Manage automated threat hunts",
		Long: `Create, list, and manage scheduled security investigations.
Hunts run playbooks on a schedule to proactively find threats.

Examples:
  trace hunt create --name nightly-scan --playbook file-analysis --param path=/tmp --schedule 12h
  trace hunt list
  trace hunt run known-malware-scan
  trace hunt pause known-malware-scan`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			if len(args) == 0 && tui.IsInteractive() {
				p := tui.NewPrompter()
				return tui.RunHuntMenu(p, app)
			}
			return cmdCobra.Help()
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new scheduled hunt",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			name, _ := cmdCobra.Flags().GetString("name")
			desc, _ := cmdCobra.Flags().GetString("description")
			schedule, _ := cmdCobra.Flags().GetString("schedule")
			playbook, _ := cmdCobra.Flags().GetString("playbook")
			rawParams, _ := cmdCobra.Flags().GetStringToString("param")

			if name == "" || schedule == "" || playbook == "" {
				return fmt.Errorf("name, schedule, and playbook are required")
			}

			params := make(map[string]any)
			for k, v := range rawParams {
				params[k] = v
			}

			h, err := app.huntManager.Create(context.Background(), name, desc, schedule, playbook, params, "self", 0)
			if err != nil {
				return fmt.Errorf("create hunt: %w", err)
			}

			fmt.Printf("Hunt %q created (ID: %s)\n", h.Name, h.ID[:12])
			fmt.Printf("  Schedule: every %s\n", h.Schedule)
			fmt.Printf("  Playbook: %s\n", h.Playbook)
			return nil
		},
	}
	createCmd.Flags().String("name", "", "Hunt name")
	createCmd.Flags().String("description", "", "Description")
	createCmd.Flags().String("schedule", "", "Schedule interval (e.g. 6h, 24h, 30m)")
	createCmd.Flags().String("playbook", "", "Playbook to execute")
	createCmd.Flags().StringToString("param", nil, "Parameters (key=value)")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all scheduled hunts",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			statusFilter, _ := cmdCobra.Flags().GetString("status")
			hunts, err := app.huntManager.List(context.Background(), statusFilter)
			if err != nil {
				return fmt.Errorf("list hunts: %w", err)
			}

			if len(hunts) == 0 {
				fmt.Println("No hunts configured. Create one with 'trace hunt create'.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "ID\tName\tPlaybook\tSchedule\tStatus\tLast Run\tNext Run")
			for _, h := range hunts {
				lr := "—"
				if h.LastRun != nil {
					lr = (*h.LastRun)[:19]
				}
				nr := "—"
				if h.NextRun != nil {
					nr = (*h.NextRun)[:19]
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					h.ID[:8], h.Name, h.Playbook, h.Schedule, h.Status, lr, nr)
			}
			w.Flush()
			return nil
		},
	}
	listCmd.Flags().String("status", "", "Filter by status (active/paused)")

	runCmd := &cobra.Command{
		Use:   "run [name]",
		Short: "Execute a hunt immediately",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: huntNameCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			h, err := app.huntManager.GetByName(context.Background(), args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Running hunt %q (%s)...\n", h.Name, h.Playbook)
			app.huntScheduler.ExecuteNow(context.Background(), h)
			fmt.Println("Done.")
			return nil
		},
	}

	pauseCmd := &cobra.Command{
		Use:   "pause [name]",
		Short: "Pause a scheduled hunt",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: huntNameCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			h, err := app.huntManager.GetByName(context.Background(), args[0])
			if err != nil {
				return err
			}
			if err := app.huntManager.Pause(context.Background(), h.ID); err != nil {
				return err
			}
			fmt.Printf("Hunt %q paused.\n", h.Name)
			return nil
		},
	}

	resumeCmd := &cobra.Command{
		Use:   "resume [name]",
		Short: "Resume a paused hunt",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: huntNameCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			h, err := app.huntManager.GetByName(context.Background(), args[0])
			if err != nil {
				return err
			}
			if err := app.huntManager.Resume(context.Background(), h.ID); err != nil {
				return err
			}
			fmt.Printf("Hunt %q resumed.\n", h.Name)
			return nil
		},
	}

	deleteCmd := &cobra.Command{
		Use:   "delete [name]",
		Short: "Delete a hunt",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: huntNameCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			h, err := app.huntManager.GetByName(context.Background(), args[0])
			if err != nil {
				return err
			}
			if err := app.huntManager.Delete(context.Background(), h.ID); err != nil {
				return err
			}
			fmt.Printf("Hunt %q deleted.\n", h.Name)
			return nil
		},
	}

	cmd.AddCommand(createCmd, listCmd, runCmd, pauseCmd, resumeCmd, deleteCmd)

	return cmd
}

func init() {
	_ = strings.Join
}
