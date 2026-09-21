package main

// Approval CLI: token-bound per-step approve/deny + DB-backed queue.
// `approve`/`deny` take a --token (per-step token JSON) or fall back to the
// legacy investigation-wide status flip with an audit row. Flag-gated
// tightening: TRACE_APPROVAL_TOKENS_REQUIRED=true makes --token mandatory.

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/yanmyoaung2004/trace/internal/audit"
	"github.com/yanmyoaung2004/trace/internal/playbook"
)

func approvalAudit(action, target string) {
	if app.auditLogger == nil {
		return
	}
	_ = audit.Audit(context.Background(), app.auditLogger,
		audit.ActorFromCtx(context.Background()), action, "approval", target,
		map[string]any{"cli": true})
}

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
			rows, err := app.invManager.ListApprovals(ctx, true)
			if err != nil {
				return fmt.Errorf("list pending approvals: %w", err)
			}
			investigations, err := app.invManager.ListPendingApprovals(ctx)
			if err != nil {
				return fmt.Errorf("list pending investigations: %w", err)
			}

			if len(rows) == 0 && len(investigations) == 0 {
				fmt.Println("No pending approvals.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			if len(rows) > 0 {
				fmt.Fprintln(w, "NONCE\tINVESTIGATION\tSTEP\tACTION\tEXPIRES")
				for _, r := range rows {
					fmt.Fprintf(w, "%.8s\t%.12s\t%d\t%s\t%s\n",
						r.Nonce, r.InvestigationID, r.StepIndex, r.Action, r.ExpiresAt)
				}
			}
			if len(investigations) > 0 {
				fmt.Fprintln(w, "ID\tIntent\tPlaybook\tCreated")
				for _, inv := range investigations {
					id := inv.ID
					if len(id) > 12 {
						id = id[:12]
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", id, inv.Intent, inv.Playbook, inv.CreatedAt)
				}
			}
			w.Flush()

			return nil
		},
	})

	approveCmd := &cobra.Command{
		Use:   "approve [investigation-id]",
		Short: "Approve a pending investigation step",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			ctx := context.Background()
			tokenJSON, _ := cmdCobra.Flags().GetString("token")
			approver, _ := cmdCobra.Flags().GetString("approver")
			if approver == "" {
				approver = os.Getenv("USER")
			}
			id, err := resolveApprovalTarget(ctx, args[0])
			if err != nil {
				return err
			}
			if tokenJSON != "" {
				tok, err := playbook.ParseApprovalToken(tokenJSON)
				if err != nil {
					return err
				}
				row, err := app.invManager.GetApproval(ctx, tok.Nonce)
				if err != nil {
					return fmt.Errorf("unknown approval nonce: %w", err)
				}
				if tok.InvestigationID != id {
					return fmt.Errorf("token bound to another investigation (deny-closed)")
				}
				if row.Status != "pending" {
					return fmt.Errorf("approval %s not pending (%s)", tok.Nonce, row.Status)
				}
				if isExpired(row.ExpiresAt) {
					_ = app.invManager.DecideApproval(ctx, tok.Nonce, "denied")
					return fmt.Errorf("approval token expired (deny-closed)")
				}
				if tok.ParamsHash != row.ParamsHash || tok.StepIndex != row.StepIndex || tok.Action != row.Action {
					return fmt.Errorf("token binding mismatch (deny-closed)")
				}
				exp, err := time.Parse(time.RFC3339, tok.Expiry)
				if err != nil || time.Now().UTC().After(exp) {
					_ = app.invManager.DecideApproval(ctx, tok.Nonce, "denied")
					return fmt.Errorf("approval token expired (deny-closed)")
				}
				if err := app.invManager.DecideApproval(ctx, tok.Nonce, "approved"); err != nil {
					return err
				}
				approvalAudit("approval.grant", id)
				fmt.Printf("Step %d of investigation %s approved\n", row.StepIndex, id)
				return nil
			}
			if os.Getenv("TRACE_APPROVAL_TOKENS_REQUIRED") == "true" {
				return fmt.Errorf("token required: re-run with --token (TRACE_APPROVAL_TOKENS_REQUIRED=true)")
			}
			if err := app.invManager.Approve(ctx, id); err != nil {
				return fmt.Errorf("approve: %w", err)
			}
			approvalAudit("approval.grant", id)
			fmt.Printf("Investigation %s approved\n", id)
			return nil
		},
	}
	approveCmd.Flags().String("token", "", "per-step approval token JSON")
	approveCmd.Flags().String("approver", "", "approver identity")

	denyCmd := &cobra.Command{
		Use:   "deny [investigation-id]",
		Short: "Deny a pending investigation step",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			ctx := context.Background()
			tokenJSON, _ := cmdCobra.Flags().GetString("token")
			id, err := resolveApprovalTarget(ctx, args[0])
			if err != nil {
				return err
			}
			if tokenJSON != "" {
				tok, err := playbook.ParseApprovalToken(tokenJSON)
				if err != nil {
					return err
				}
				if err := app.invManager.DecideApproval(ctx, tok.Nonce, "denied"); err != nil {
					return err
				}
				approvalAudit("approval.deny", id)
				fmt.Printf("Step of investigation %s denied\n", id)
				return nil
			}
			if err := app.invManager.Deny(ctx, id); err != nil {
				return fmt.Errorf("deny: %w", err)
			}
			approvalAudit("approval.deny", id)
			fmt.Printf("Investigation %s denied\n", id)
			return nil
		},
	}
	denyCmd.Flags().String("token", "", "per-step approval token JSON (nonce)")

	// Aliases used by existing tests/golden help.
	approveCmd.Aliases = []string{}
	denyCmd.Aliases = []string{}

	cmd.AddCommand(approveCmd, denyCmd)

	return cmd
}

// resolveApprovalTarget accepts a full ID or a hex prefix (traversal-safe via
// Manager.GetByPrefix allowlist).
func resolveApprovalTarget(ctx context.Context, idOrPrefix string) (string, error) {
	if inv, err := app.invManager.Get(ctx, idOrPrefix); err == nil {
		return inv.ID, nil
	}
	inv, err := app.invManager.GetByPrefix(ctx, idOrPrefix)
	if err != nil {
		return "", fmt.Errorf("investigation not found: %s", idOrPrefix)
	}
	return inv.ID, nil
}


func isExpired(rfc3339 string) bool {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return true
	}
	return time.Now().UTC().After(t)
}
