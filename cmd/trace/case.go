package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/yanmyoaung2004/trace/internal/tui"
	"github.com/spf13/cobra"
)

func newCaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "case",
		Short: "Manage security cases",
		Long: `Create, view, and manage security investigation cases with timeline, IOCs, and evidence.

Examples:
  trace case create --title "Phishing campaign" --severity high
  trace case list
  trace case view <id>
  trace case note <id> "Found additional indicators"
  trace case ioc <id> --type ip --value 10.0.0.5
  trace case assign <id> --to analyst@example.com
  trace case close <id> --resolution "resolved"`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			if len(args) == 0 && tui.IsInteractive() {
				p := tui.NewPrompter()
				return tui.RunCaseMenu(p, app)
			}
			return cmdCobra.Help()
		},
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new case",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			title, _ := cmdCobra.Flags().GetString("title")
			desc, _ := cmdCobra.Flags().GetString("description")
			severity, _ := cmdCobra.Flags().GetString("severity")
			if title == "" {
				return fmt.Errorf("title is required")
			}
			c, err := app.caseManager.Create(context.Background(), title, desc, severity)
			if err != nil {
				return err
			}
			fmt.Printf("Case created: %s (%s)\n", c.ID[:12], c.Title)
			return nil
		},
	}
	createCmd.Flags().String("title", "", "Case title")
	createCmd.Flags().String("description", "", "Description")
	createCmd.Flags().String("severity", "medium", "Severity (low/medium/high/critical)")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List cases",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			status, _ := cmdCobra.Flags().GetString("status")
			severity, _ := cmdCobra.Flags().GetString("severity")
			casesList, err := app.caseManager.List(context.Background(), status, severity)
			if err != nil {
				return err
			}
			if len(casesList) == 0 {
				fmt.Println("No cases found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "ID\tTitle\tStatus\tSeverity\tAssignee\tCreated")
			for _, c := range casesList {
				as := c.Assignee
				if as == "" {
					as = "—"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					c.ID[:8], c.Title, c.Status, c.Severity, as, c.CreatedAt[:19])
			}
			w.Flush()
			return nil
		},
	}
	listCmd.Flags().String("status", "", "Filter by status (open/investigating/resolved/closed)")
	listCmd.Flags().String("severity", "", "Filter by severity (low/medium/high/critical)")

	viewCmd := &cobra.Command{
		Use:   "view [id]",
		Short: "View case details",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: caseIDCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			c, err := app.caseManager.Get(context.Background(), args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Case: %s\n", c.ID)
			fmt.Printf("Title:      %s\n", c.Title)
			fmt.Printf("Status:     %s\n", c.Status)
			fmt.Printf("Severity:   %s\n", c.Severity)
			fmt.Printf("Assignee:   %s\n", c.Assignee)
			fmt.Printf("Created:    %s\n", c.CreatedAt[:19])
			fmt.Printf("Updated:    %s\n", c.UpdatedAt[:19])
			if c.Description != "" {
				fmt.Printf("Description: %s\n", c.Description)
			}
			if c.ClosedAt != nil {
				fmt.Printf("Closed:     %s\n", (*c.ClosedAt)[:19])
			}
			if c.Resolution != "" {
				fmt.Printf("Resolution: %s\n", c.Resolution)
			}

			events, _ := app.caseManager.GetEvents(context.Background(), c.ID)
			if len(events) > 0 {
				fmt.Println("\nTimeline:")
				for _, e := range events {
					fmt.Printf("  [%s] %s: %s\n", e.CreatedAt[:19], e.EventType, e.Content)
				}
			}

			iocs, _ := app.caseManager.GetIOCs(context.Background(), c.ID)
			if len(iocs) > 0 {
				fmt.Println("\nIOCs:")
				for _, i := range iocs {
					fmt.Printf("  %s: %s", i.IOCType, i.Value)
					if i.Description != "" {
						fmt.Printf(" (%s)", i.Description)
					}
					fmt.Println()
				}
			}
			return nil
		},
	}

	noteCmd := &cobra.Command{
		Use:   "note [id] [content]",
		Short: "Add a note to a case",
		Args:  cobra.ExactArgs(2),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return caseIDCompletionFunc(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			_, err := app.caseManager.AddEvent(context.Background(), args[0], "note", args[1], "manual")
			return err
		},
	}

	iocCmd := &cobra.Command{
		Use:   "ioc [id]",
		Short: "Add an IOC to a case",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: caseIDCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			iocType, _ := cmdCobra.Flags().GetString("type")
			value, _ := cmdCobra.Flags().GetString("value")
			desc, _ := cmdCobra.Flags().GetString("description")
			if iocType == "" || value == "" {
				return fmt.Errorf("type and value are required")
			}
			_, err := app.caseManager.AddIOC(context.Background(), args[0], iocType, value, desc)
			return err
		},
	}
	iocCmd.Flags().String("type", "", "IOC type (ip, domain, url, hash, email, filepath)")
	iocCmd.Flags().String("value", "", "IOC value")
	iocCmd.Flags().String("description", "", "Description")

	assignCmd := &cobra.Command{
		Use:   "assign [id]",
		Short: "Assign a case to an analyst",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: caseIDCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			to, _ := cmdCobra.Flags().GetString("to")
			if to == "" {
				return fmt.Errorf("--to is required")
			}
			return app.caseManager.Assign(context.Background(), args[0], to)
		},
	}
	assignCmd.Flags().String("to", "", "Assignee email or name")

	closeCmd := &cobra.Command{
		Use:   "close [id]",
		Short: "Close a case",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: caseIDCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			resolution, _ := cmdCobra.Flags().GetString("resolution")
			return app.caseManager.Resolve(context.Background(), args[0], resolution)
		},
	}
	closeCmd.Flags().String("resolution", "", "Resolution notes")

	exportCmd := &cobra.Command{
		Use:   "export [id]",
		Short: "Export a case as JSON",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: caseIDCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			c, err := app.caseManager.Get(context.Background(), args[0])
			if err != nil {
				return err
			}
			events, _ := app.caseManager.GetEvents(context.Background(), c.ID)
			iocs, _ := app.caseManager.GetIOCs(context.Background(), c.ID)

			output := map[string]any{
				"case":   c,
				"events": events,
				"iocs":   iocs,
			}
			data, _ := json.MarshalIndent(output, "", "  ")
			fmt.Println(string(data))
			return nil
		},
	}

	exportPdfCmd := &cobra.Command{
		Use:   "export-pdf [id]",
		Short: "Export a case as PDF",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: caseIDCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			output, _ := cmdCobra.Flags().GetString("output")
			pdfData, err := app.caseManager.ExportPDF(context.Background(), args[0])
			if err != nil {
				return err
			}
			if output != "" {
				if err := os.WriteFile(output, pdfData, 0644); err != nil {
					return fmt.Errorf("write pdf: %w", err)
				}
				fmt.Printf("PDF saved to %s (%d bytes)\n", output, len(pdfData))
			} else {
				os.Stdout.Write(pdfData)
			}
			return nil
		},
	}
	exportPdfCmd.Flags().String("output", "o", "output file path")

	createCmd.RegisterFlagCompletionFunc("severity", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"low", "medium", "high", "critical"}, cobra.ShellCompDirectiveNoFileComp
	})
	listCmd.RegisterFlagCompletionFunc("status", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"open", "investigating", "resolved", "closed"}, cobra.ShellCompDirectiveNoFileComp
	})
	listCmd.RegisterFlagCompletionFunc("severity", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"low", "medium", "high", "critical"}, cobra.ShellCompDirectiveNoFileComp
	})

	evidenceCmd := &cobra.Command{
		Use:   "evidence [id]",
		Short: "Attach evidence to a case",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: caseIDCompletionFunc,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			file, _ := cmdCobra.Flags().GetString("file")
			name, _ := cmdCobra.Flags().GetString("name")
			mime, _ := cmdCobra.Flags().GetString("mime")
			if file == "" {
				return fmt.Errorf("--file is required")
			}
			if name == "" {
				name = filepath.Base(file)
			}
			err := app.caseManager.AddEvidence(context.Background(), args[0], name, file, mime, "cli")
			if err != nil {
				return fmt.Errorf("add evidence: %w", err)
			}
			fmt.Printf("Evidence attached: %s\n", name)
			return nil
		},
	}
	evidenceCmd.Flags().String("file", "", "Path to evidence file")
	evidenceCmd.Flags().String("name", "", "Display name (defaults to filename)")
	evidenceCmd.Flags().String("mime", "application/octet-stream", "MIME type")

	cmd.AddCommand(createCmd, listCmd, viewCmd, noteCmd, iocCmd, assignCmd, closeCmd, exportCmd, exportPdfCmd, evidenceCmd)
	return cmd
}

func caseIDCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	cs, err := app.caseManager.List(context.Background(), "", "")
	if err != nil || len(cs) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var matches []string
	for _, c := range cs {
		short := c.ID
		if len(short) > 8 {
			short = short[:8]
		}
		if strings.HasPrefix(short, toComplete) {
			matches = append(matches, short)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}
