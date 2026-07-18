package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newApprovalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approval",
		Short: "Manage HITL approval requests",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "pending",
		Short: "List investigations waiting for approval",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			ctx := context.Background()
			investigations, err := app.invManager.ListPendingApprovals(ctx)
			if err != nil {
				return fmt.Errorf("list pending approvals: %w", err)
			}

			if len(investigations) == 0 {
				fmt.Println("No pending approvals.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tIntent\tPlaybook\tCreated")
			for _, inv := range investigations {
				id := inv.ID
				if len(id) > 12 {
					id = id[:12]
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", id, inv.Intent, inv.Playbook, inv.CreatedAt)
			}
			w.Flush()

			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "approve [investigation-id]",
		Short: "Approve a pending investigation step",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			ctx := context.Background()
			if err := app.invManager.Approve(ctx, args[0]); err != nil {
				return fmt.Errorf("approve: %w", err)
			}
			fmt.Printf("Investigation %s approved\n", args[0])
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "deny [investigation-id]",
		Short: "Deny a pending investigation step",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			ctx := context.Background()
			if err := app.invManager.Deny(ctx, args[0]); err != nil {
				return fmt.Errorf("deny: %w", err)
			}
			fmt.Printf("Investigation %s denied\n", args[0])
			return nil
		},
	})

	return cmd
}
