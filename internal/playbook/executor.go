package playbook

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/innoigniter/edge/internal/plugin"
	"github.com/innoigniter/edge/internal/investigation"
)

type Executor struct {
	registry   *plugin.Registry
	invManager *investigation.Manager
	logWriter  *investigation.LogWriter
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
	}

	e.logWriter.WriteEvent(inv.ID, "playbook_started", map[string]any{
		"playbook": pb.Name,
		"input":    input,
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
					"step":       i,
					"agent":      step.Agent,
					"action":     step.Action,
					"condition":  step.If,
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

			approved, err := e.waitForApproval(ctx, inv.ID, step.Label)
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
			"params": paramsMap,
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
			"output": output,
		})
	}

	e.invManager.UpdateStatus(ctx, inv.ID, "completed")

	e.logWriter.WriteEvent(inv.ID, "playbook_completed", map[string]any{
		"playbook": pb.Name,
		"results":  scope.Results,
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

func (e *Executor) waitForApproval(ctx context.Context, investigationID, label string) (bool, error) {
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}

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

func (e *Executor) PendingApprovals(ctx context.Context) ([]ApprovalRequest, error) {
	return nil, fmt.Errorf("not yet supported without DB query")
}

func formatOutput(output map[string]any) string {
	b, _ := json.MarshalIndent(output, "", "  ")
	return string(b)
}
