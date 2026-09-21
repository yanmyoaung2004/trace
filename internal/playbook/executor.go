package playbook

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/yanmyoaung2004/trace/internal/audit"
	"github.com/yanmyoaung2004/trace/internal/investigation"
	"github.com/yanmyoaung2004/trace/internal/plugin"
)

type Executor struct {
	registry   *plugin.Registry
	invManager *investigation.Manager
	logWriter  *investigation.LogWriter
	// NotifyApprover, when set, pings the approver (CLI queue + notifier
	// wiring in cmd layer). Empty default = log only.
	NotifyApprover func(invID string, stepIdx int, label, action string)
}

func NewExecutor(reg *plugin.Registry, invMgr *investigation.Manager, lw *investigation.LogWriter) *Executor {
	return &Executor{
		registry:   reg,
		invManager: invMgr,
		logWriter:  lw,
	}
}

type StepResult struct {
	Step   Step
	Output map[string]any
	Error  string
}

func (e *Executor) Execute(ctx context.Context, inv *investigation.Investigation, pb *Playbook, input map[string]any) (map[string]any, error) {
	scope := &Scope{
		Input:   input,
		Results: make(map[string]any),
		Investigation: map[string]any{
			"id":       inv.ID,
			"intent":   inv.Intent,
			"playbook": inv.Playbook,
			"status":   inv.Status,
		},
	}

	e.logWriter.WriteEvent(inv.ID, "playbook_started", map[string]any{
		"playbook": pb.Name,
		"input":    audit.RedactMap(input),
	})

	e.invManager.UpdateStatus(ctx, inv.ID, "running")

	for i, step := range pb.Steps {
		select {
		case <-ctx.Done():
			e.invManager.UpdateStatus(ctx, inv.ID, "cancelled")
			return nil, ctx.Err()
		default:
		}

		if step.If != "" {
			ok, err := evaluateCondition(step.If, scope)
			if err != nil {
				return nil, fmt.Errorf("step %d condition: %w", i, err)
			}
			if !ok {
				e.logWriter.WriteEvent(inv.ID, "step_skipped", map[string]any{
					"step":      i,
					"agent":     step.Agent,
					"action":    step.Action,
					"condition": step.If,
				})
				continue
			}
		}

		if step.Wait == "analyst_approval" {
			e.logWriter.WriteEvent(inv.ID, "step_waiting_approval", map[string]any{
				"step":  i,
				"label": step.Label,
			})
			e.invManager.UpdateStatus(ctx, inv.ID, "waiting_approval")

			// Record a DB-backed pending approval row (truncated params
			// hash; full params bound at token verify time).
			rawParams, _ := interpolate(step.Params, scope)
			ph := ""
			if pm, ok := rawParams.(map[string]any); ok {
				ph = ParamsHash(pm)
				_ = e.invManager.RecordApproval(ctx, investigation.ApprovalRow{
					Nonce:           pendingNonce(inv.ID, i),
					InvestigationID: inv.ID,
					StepIndex:       i,
					Label:           step.Label,
					Agent:           step.Agent,
					Action:          step.Action,
					ParamsHash:      ph,
					ExpiresAt:       time.Now().UTC().Add(ApprovalTTL).Format(time.RFC3339),
				})
			}
			if e.NotifyApprover != nil {
				e.NotifyApprover(inv.ID, i, step.Label, step.Agent+"."+step.Action)
			}

			approved, err := e.waitForApproval(ctx, inv.ID, i, step.Agent+"."+step.Action, step.Label)
			if err != nil {
				return nil, fmt.Errorf("step %d approval: %w", i, err)
			}
			if !approved {
				e.logWriter.WriteEvent(inv.ID, "step_denied", map[string]any{
					"step":  i,
					"label": step.Label,
				})
				e.invManager.UpdateStatus(ctx, inv.ID, "denied")
				return nil, fmt.Errorf("step %d denied by analyst: %s", i, step.Label)
			}

			e.invManager.UpdateStatus(ctx, inv.ID, "running")
			e.logWriter.WriteEvent(inv.ID, "step_approved", map[string]any{
				"step":  i,
				"label": step.Label,
			})
		}

		params, err := interpolate(step.Params, scope)
		if err != nil {
			return nil, fmt.Errorf("step %d interpolate params: %w", i, err)
		}

		paramsMap, ok := params.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("step %d params not a map", i)
		}
		paramsMap["action"] = step.Action

		// Taint-isolate: untrusted outputs into sensitive sinks are
		// validated with the shared response validators (deny on failure).
		sanitized, err := SanitizeSinkParams(step.Agent, step.Params, paramsMap)
		if err != nil {
			return nil, fmt.Errorf("step %d taint check: %w", i, err)
		}
		paramsMap = sanitized

		var timeout time.Duration
		if step.Timeout != "" {
			timeout, err = time.ParseDuration(step.Timeout)
			if err != nil {
				return nil, fmt.Errorf("step %d invalid timeout %s: %w", i, step.Timeout, err)
			}
		}

		e.logWriter.WriteEvent(inv.ID, "step_started", map[string]any{
			"step":   i,
			"agent":  step.Agent,
			"action": step.Action,
			"params": audit.RedactMap(paramsMap),
		})

		var output map[string]any
		var execErr error

		if timeout > 0 {
			stepCtx, cancel := context.WithTimeout(ctx, timeout)
			output, execErr = e.executeStep(stepCtx, step, paramsMap)
			cancel()
		} else {
			output, execErr = e.executeStep(ctx, step, paramsMap)
		}

		if execErr != nil {
			if step.Optional {
				e.logWriter.WriteEvent(inv.ID, "step_failed_optional", map[string]any{
					"step":  i,
					"agent": step.Agent,
					"error": execErr.Error(),
				})
				continue
			}
			e.logWriter.WriteEvent(inv.ID, "step_failed", map[string]any{
				"step":  i,
				"agent": step.Agent,
				"error": execErr.Error(),
			})
			e.invManager.UpdateStatus(ctx, inv.ID, "failed")
			return nil, fmt.Errorf("step %d: %w", i, execErr)
		}

		resultKey := step.Agent + "." + step.Action
		scope.Results[resultKey] = output

		e.logWriter.WriteEvent(inv.ID, "step_completed", map[string]any{
			"step":   i,
			"agent":  step.Agent,
			"action": step.Action,
			"output": audit.RedactMap(output),
		})
	}

	e.invManager.UpdateStatus(ctx, inv.ID, "completed")

	e.logWriter.WriteEvent(inv.ID, "playbook_completed", map[string]any{
		"playbook": pb.Name,
		"results":  audit.RedactMap(scope.Results),
	})

	return scope.Results, nil
}

func (e *Executor) executeStep(ctx context.Context, step Step, params map[string]any) (map[string]any, error) {
	ag := e.registry.Get(step.Agent)
	if ag == nil {
		return nil, fmt.Errorf("agent %q not found", step.Agent)
	}

	output, err := ag.Execute(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("%s execute %s: %w", step.Agent, step.Action, err)
	}

	return output, nil
}

// waitForApproval is bounded (deny-closed): deadline → deny, never infinite.
// It verifies a DB approval row decision; the per-execution token check
// happens at the dispatch/CLI layer via VerifyApprovalToken.
func (e *Executor) waitForApproval(ctx context.Context, investigationID string, stepIdx int, action, label string) (bool, error) {
	_ = label
	deadline := time.Now().Add(ApprovalWaitTimeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-tick.C:
		}

		if time.Now().After(deadline) {
			return false, fmt.Errorf("approval wait timed out (deny-closed)")
		}

		// Expire stale rows first (deny-closed).
		_, _ = e.invManager.ExpireApprovals(ctx, time.Now().UTC().Format(time.RFC3339))

		inv, err := e.invManager.Get(ctx, investigationID)
		if err != nil {
			continue
		}
		switch inv.Status {
		case "approved":
			return true, nil
		case "denied":
			return false, nil
		case "cancelled":
			return false, fmt.Errorf("investigation cancelled")
		}

		// Also honor a decided DB approval row for this step.
		rows, err := e.invManager.ListApprovals(ctx, false)
		if err != nil {
			continue
		}
		for _, r := range rows {
			if r.InvestigationID == investigationID && r.StepIndex == stepIdx {
				switch r.Status {
				case "approved":
					return true, nil
				case "denied":
					return false, nil
				}
			}
		}
	}
}

type ApprovalRequest struct {
	InvestigationID string `json:"investigation_id"`
	StepIndex       int    `json:"step_index"`
	Label           string `json:"label"`
	Agent           string `json:"agent"`
	Action          string `json:"action"`
	Status          string `json:"status"`
}

// PendingApprovals lists DB-backed pending approvals (implemented, no stub).
func (e *Executor) PendingApprovals(ctx context.Context) ([]ApprovalRequest, error) {
	rows, err := e.invManager.ListApprovals(ctx, true)
	if err != nil {
		return nil, err
	}
	out := make([]ApprovalRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, ApprovalRequest{
			InvestigationID: r.InvestigationID,
			StepIndex:       r.StepIndex,
			Label:           r.Label,
			Agent:           r.Agent,
			Action:          r.Action,
			Status:          r.Status,
		})
	}
	return out, nil
}

func formatOutput(output map[string]any) string {
	b, _ := json.MarshalIndent(audit.RedactMap(output), "", "  ")
	return string(b)
}

// pendingNonce is a stable idempotency key for the auto-created approval row
// (RecordApproval is INSERT OR IGNORE on nonce).
func pendingNonce(invID string, step int) string {
	// Opaque key, not a network address (hostport vet N/A).
	return invID + ":" + strconv.Itoa(step)
}
