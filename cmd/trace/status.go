package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/yanmyoaung2004/trace/internal/tui"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [investigation-id]",
		Short: "View investigation status",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			id := ""
			if len(args) == 1 {
				id = args[0]
			} else if tui.IsInteractive() {
				invs, err := app.ListRecentInvestigations(20)
				if err != nil {
					return fmt.Errorf("list investigations: %w", err)
				}
				if len(invs) == 0 {
					return fmt.Errorf("no investigations found")
				}
				opts := make([]string, len(invs))
				for i, inv := range invs {
				cf := ""
				if inv.Confidence > 0 {
					cf = fmt.Sprintf(" (%.0f%%)", inv.Confidence*100)
				}
				label := fmt.Sprintf("%s — %s [%s]%s", inv.ID[:8], inv.Intent, inv.Status, cf)
					opts[i] = label
				}
				p := tui.NewPrompter()
				selected, err := p.Select("Select an investigation", opts)
				if err != nil {
					return err
				}
				for i, opt := range opts {
					if opt == selected {
						id = invs[i].ID
						break
					}
				}
			}
			if id == "" {
				return fmt.Errorf("investigation ID is required")
			}

			inv, err := app.invManager.Get(ctx, id)
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
