package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newHistoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history",
		Short: "List recent investigations",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			ctx := context.Background()
			limit, _ := cmdCobra.Flags().GetInt("limit")
			investigations, err := app.invManager.ListRecent(ctx, limit)
			if err != nil {
				return fmt.Errorf("list investigations: %w", err)
			}

			if len(investigations) == 0 {
				fmt.Println("No investigations found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tStatus\tIntent\tPlaybook\tCreated")
			for _, inv := range investigations {
				id := inv.ID
				if len(id) > 12 {
					id = id[:12]
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", id, inv.Status, truncate(inv.Intent, 40), inv.Playbook, inv.CreatedAt)
			}
			w.Flush()

			return nil
		},
	}

	cmd.Flags().IntP("limit", "n", 20, "number of investigations to show")
	return cmd
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
