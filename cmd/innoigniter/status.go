package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [investigation-id]",
		Short: "View investigation status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			inv, err := app.invManager.Get(ctx, args[0])
			if err != nil {
				return fmt.Errorf("get investigation: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "ID:\t%s\n", inv.ID)
			fmt.Fprintf(w, "Status:\t%s\n", inv.Status)
			fmt.Fprintf(w, "Intent:\t%s\n", inv.Intent)
			fmt.Fprintf(w, "Playbook:\t%s\n", inv.Playbook)
			if inv.Confidence != nil {
				fmt.Fprintf(w, "Confidence:\t%.0f%%\n", *inv.Confidence*100)
			}
			fmt.Fprintf(w, "Created:\t%s\n", inv.CreatedAt)
			fmt.Fprintf(w, "Updated:\t%s\n", inv.UpdatedAt)
			w.Flush()

			return nil
		},
	}
}
