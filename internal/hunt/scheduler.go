package hunt

import (
	"context"
	"fmt"
	"log"
	"sync"
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
	poolSize   int
	sem        chan struct{}

	mu           sync.Mutex
	failures     map[string]int
	backoffUntil map[string]time.Time
	alertFunc    func(huntName, msg string)
}

// SetAlertFunc routes hunt failure alerts (backoff/exhausted) to a notifier.
func (s *Scheduler) SetAlertFunc(fn func(huntName, msg string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertFunc = fn
}

func (s *Scheduler) recordFailure(h *Hunt, msg string) {
	s.mu.Lock()
	if s.failures == nil {
		s.failures = map[string]int{}
	}
	if s.backoffUntil == nil {
		s.backoffUntil = map[string]time.Time{}
	}
	s.failures[h.ID]++
	n := s.failures[h.ID]
	delay := time.Duration(n*n) * time.Minute
	if delay > 30*time.Minute {
		delay = 30 * time.Minute
	}
	s.backoffUntil[h.ID] = time.Now().Add(delay)
	fn := s.alertFunc
	s.mu.Unlock()
	log.Printf("[hunt] %s: failure %d (%s), backing off %s", h.Name, n, msg, delay)
	if fn != nil {
		fn(h.Name, msg)
	}
}

func (s *Scheduler) recordSuccess(h *Hunt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, h.ID)
	delete(s.backoffUntil, h.ID)
}

func (s *Scheduler) inBackoff(h *Hunt) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.backoffUntil[h.ID]
	return ok && time.Now().Before(until)
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
		poolSize:   4,
		sem:        make(chan struct{}, 4),
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

	// Bounded pool: one 10m hunt cannot head-of-line-block the rest.
	var wg sync.WaitGroup
	for _, h := range hunts {
		if s.inBackoff(h) {
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			log.Printf("[hunt] pool full, deferring %s", h.Name)
			continue
		}
		wg.Add(1)
		go func(hh *Hunt) {
			defer wg.Done()
			defer func() { <-s.sem }()
			s.runHunt(ctx, hh)
		}(h)
	}
	wg.Wait()
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
	fresh, err := s.manager.Get(ctx, h.ID)
	if err != nil {
		s.recordFailure(h, "get: "+err.Error())
		return
	}
	expected := ""
	if fresh.NextRun != nil {
		expected = *fresh.NextRun
	}
	newNext := computeNextRun(fresh.Schedule)
	if newNext == "" {
		newNext = time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	}
	claimed, err := s.manager.ClaimRun(ctx, h.ID, expected, newNext)
	if err != nil || !claimed {
		return
	}
	h.NextRun = &newNext
	pb := s.playbooks.Get(h.Playbook)
	if pb == nil {
		log.Printf("[hunt] %s: playbook %q not found, pausing", h.Name, h.Playbook)
		s.manager.Pause(ctx, h.ID)
		s.recordFailure(h, "playbook not found")
		return
	}
	inv, err := s.invManager.Create(huntCtx, fmt.Sprintf("Hunt: %s", h.Name), h.Playbook)
	if err != nil {
		log.Printf("[hunt] %s: create investigation: %v", h.Name, err)
		s.recordFailure(h, "create investigation: "+err.Error())
		return
	}
	log.Printf("[hunt] %s: running playbook %s (investigation: %s)", h.Name, h.Playbook, inv.ID[:8])
	results, err := s.executor.Execute(huntCtx, inv, pb, h.Params)
	if err != nil {
		log.Printf("[hunt] %s: playbook failed: %v", h.Name, err)
		s.invManager.UpdateStatus(huntCtx, inv.ID, "failed")
		s.recordFailure(h, "playbook: "+err.Error())
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
		s.recordFailure(h, "report: "+err.Error())
		return
	}
	if conf, ok := reportOutput["confidence"].(float64); ok && conf > 0 {
		log.Printf("[hunt] %s: completed with confidence %.0f%%", h.Name, conf*100)
	}
	s.recordSuccess(h)
}

func (s *Scheduler) ExecuteNow(ctx context.Context, h *Hunt) {
	s.runHunt(ctx, h)
}

func init() {
	_ = fmt.Sprintf
}
