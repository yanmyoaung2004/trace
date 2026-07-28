package alertmgr

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// SuppressionRule defines when to suppress an alert.
type SuppressionRule struct {
	ID          string
	RuleID      string   // SIEM rule ID to match (empty = any)
	Source      string   // Source IP/hostname to match (empty = any)
	Duration    time.Duration // How long to suppress after first match
	MaxRate     int      // Max alerts per hour (0 = unlimited)
	Threshold   int      // Min count before alerting (0 = immediate)
	ThresholdWindow time.Duration // Time window for threshold counting
	CreatedAt   time.Time
}

// AlertEvent represents a triggered alert to be checked against rules.
type AlertEvent struct {
	Title      string
	RuleID     string
	Source     string
	Severity   int
	Raw        map[string]any
}

// Manager handles alert fatigue: suppression, threshold, decay, aggregation.
type Manager struct {
	mu       sync.Mutex
	suppress []SuppressionRule
	counters map[string]*ruleCounter // ruleID -> counter
}

type ruleCounter struct {
	hitCount    int
	lastHit     time.Time
	suppressUntil time.Time
}

func New() *Manager {
	return &Manager{
		counters: make(map[string]*ruleCounter),
	}
}

// AddSuppressionRule adds a suppression rule.
func (m *Manager) AddSuppressionRule(rule SuppressionRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.suppress = append(m.suppress, rule)
	log.Printf("[alertmgr] suppression rule added: rule=%q source=%q duration=%s",
		rule.RuleID, rule.Source, rule.Duration)
}

// ShouldSuppress checks if an alert should be suppressed.
// Returns (suppress bool, reason string).
func (m *Manager) ShouldSuppress(alert AlertEvent) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := alert.RuleID
	rc, exists := m.counters[key]
	if !exists {
		rc = &ruleCounter{}
		m.counters[key] = rc
	}

	now := time.Now()

	// Check active suppression from previous decay
	if exists && rc.suppressUntil.After(now) {
		remaining := rc.suppressUntil.Sub(now).Round(time.Second)
		return true, fmt.Sprintf("suppressed for %v (rule=%s)", remaining, alert.RuleID)
	}

	// Only increment on the actual pass-through
	rc.hitCount++
	rc.lastHit = now

	// Check suppression rules (threshold, max-rate)
	for _, rule := range m.suppress {
		if rule.RuleID != "" && rule.RuleID != alert.RuleID {
			continue
		}
		if rule.Source != "" && rule.Source != alert.Source {
			continue
		}

		// Threshold check
		if rule.Threshold > 0 {
			windowStart := now.Add(-rule.ThresholdWindow)
			// Count hits within the window by scanning all counters
			if rc.lastHit.Before(windowStart) {
				rc.hitCount = 1
			}

			if rc.hitCount < rule.Threshold {
				return true, fmt.Sprintf("below threshold %d/%d (rule=%s)",
					rc.hitCount, rule.Threshold, alert.RuleID)
			}
		}

		// Max rate check
		if rule.MaxRate > 0 {
			if rc.hitCount > rule.MaxRate {
				rc.suppressUntil = now.Add(rule.Duration)
				return true, fmt.Sprintf("rate limit %d/h exceeded (rule=%s)", rule.MaxRate, alert.RuleID)
			}
		}
	}

	// Time-based decay: repeated alerts get increasing suppression
	if rc.hitCount > 1 && rc.hitCount <= 10 {
		decayDelay := time.Duration(rc.hitCount) * time.Minute
		rc.suppressUntil = now.Add(decayDelay)
		log.Printf("[alertmgr] decay suppress %s for %v (hit #%d)", alert.RuleID, decayDelay, rc.hitCount)
	}
	if rc.hitCount > 10 {
		rc.suppressUntil = now.Add(1 * time.Hour)
	}

	return false, ""
}

// Reset clears counters for a given rule (e.g., after manual review).
func (m *Manager) Reset(ruleID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.counters, ruleID)
	log.Printf("[alertmgr] reset counters for rule=%s", ruleID)
}

// Stats returns current counter state for inspection.
func (m *Manager) Stats() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats := make(map[string]any)
	for ruleID, rc := range m.counters {
		stats[ruleID] = map[string]any{
			"hit_count":      rc.hitCount,
			"last_hit":       rc.lastHit.Format(time.RFC3339),
			"suppress_until": rc.suppressUntil.Format(time.RFC3339),
		}
	}
	return stats
}
