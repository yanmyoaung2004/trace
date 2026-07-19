package hunt

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
	"github.com/yanmyoaung2004/trace/internal/investigation"
	"github.com/yanmyoaung2004/trace/internal/playbook"
)

type Scheduler struct {
	manager    *Manager
	invManager *investigation.Manager
	executor   *playbook.Executor
	playbooks  *playbook.Engine
	dispatch   agent.Agent
	logWriter  *investigation.LogWriter
	tick       time.Duration
}

func NewScheduler(mgr *Manager, invMgr *investigation.Manager, exec *playbook.Executor, pbs *playbook.Engine, disp agent.Agent, lw *investigation.LogWriter) *Scheduler {
	return &Scheduler{
		manager:    mgr,
		invManager: invMgr,
		executor:   exec,
		playbooks:  pbs,
		dispatch:   disp,
		logWriter:  lw,
		tick:       60 * time.Second,
	}
}

func (s *Scheduler) Start(ctx context.Context) {
	log.Printf("[hunt] scheduler started (check every %s)", s.tick)
	ticker := time.NewTicker(s.tick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[hunt] scheduler stopped")
			return
		case <-ticker.C:
			s.check(ctx)
		}
	}
}

func (s *Scheduler) check(ctx context.Context) {
	hunts, err := s.manager.DueHunts(ctx)
	if err != nil {
		log.Printf("[hunt] check error: %v", err)
		return
	}

	if len(hunts) == 0 && time.Now().Second() < 5 {
		s.seedDefaults(ctx)
	}
	if len(hunts) == 0 {
		return
	}

	for _, h := range hunts {
		s.runHunt(ctx, h)
	}
}

func (s *Scheduler) seedDefaults(ctx context.Context) {
	defaults := BuildDefaultHunts()
	for _, d := range defaults {
		existing, _ := s.manager.GetByName(ctx, d.Name)
		if existing == nil {
			h, err := s.manager.Create(ctx, d.Name, d.Description, d.Schedule, d.Playbook, d.Params, d.Scope, d.NotifySeverity)
			if err != nil {
				log.Printf("[hunt] seed %s: %v", d.Name, err)
			} else {
				log.Printf("[hunt] seeded default hunt: %s (%s)", h.Name, h.Schedule)
			}
		}
	}
}

func (s *Scheduler) runHunt(ctx context.Context, h *Hunt) {
	huntCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	pb := s.playbooks.Get(h.Playbook)
	if pb == nil {
		log.Printf("[hunt] %s: playbook %q not found, pausing", h.Name, h.Playbook)
		s.manager.Pause(ctx, h.ID)
		return
	}

	inv, err := s.invManager.Create(huntCtx, fmt.Sprintf("Hunt: %s", h.Name), h.Playbook)
	if err != nil {
		log.Printf("[hunt] %s: create investigation: %v", h.Name, err)
		s.manager.MarkRun(ctx, h.ID)
		return
	}

	log.Printf("[hunt] %s: running playbook %s (investigation: %s)", h.Name, h.Playbook, inv.ID[:8])

	results, err := s.executor.Execute(huntCtx, inv, pb, h.Params)
	if err != nil {
		log.Printf("[hunt] %s: playbook failed: %v", h.Name, err)
		s.invManager.UpdateStatus(huntCtx, inv.ID, "failed")
		s.manager.MarkRun(ctx, h.ID)
		return
	}

	reportOutput, err := s.dispatch.Execute(huntCtx, agent.Input{
		"action":           "synthesize_report",
		"results":          results,
		"investigation_id": inv.ID,
		"intent":           fmt.Sprintf("Hunt: %s", h.Name),
	})
	if err != nil {
		log.Printf("[hunt] %s: report: %v", h.Name, err)
		s.manager.MarkRun(ctx, h.ID)
		return
	}

	if conf, ok := reportOutput["confidence"].(float64); ok && conf > 0 {
		log.Printf("[hunt] %s: completed with confidence %.0f%%", h.Name, conf*100)
	}

	s.manager.MarkRun(ctx, h.ID)
}

func (s *Scheduler) ExecuteNow(ctx context.Context, h *Hunt) {
	s.runHunt(ctx, h)
}

func init() {
	_ = fmt.Sprintf
}
