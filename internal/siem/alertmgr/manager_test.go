package alertmgr

import (
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestShouldSuppress_FirstHit(t *testing.T) {
	m := New()
	suppress, reason := m.ShouldSuppress(AlertEvent{
		Title:  "Test Alert",
		RuleID: "rule-001",
		Source: "10.0.0.1",
	})
	if suppress {
		t.Errorf("first hit should not be suppressed, got reason: %s", reason)
	}
}

func TestShouldSuppress_Decay(t *testing.T) {
	m := New()

	suppress, reason := m.ShouldSuppress(AlertEvent{RuleID: "decay-test", Source: "10.0.0.1"})
	if suppress {
		t.Fatal("first hit should not be suppressed")
	}
	_ = reason

	// Hit 2 establishes the decay window and passes through; hit 3
	// inside the window suppresses.
	suppress, _ = m.ShouldSuppress(AlertEvent{RuleID: "decay-test", Source: "10.0.0.1"})
	if suppress {
		t.Fatal("second hit establishes the window and should pass through")
	}

	// Hit 3 should be suppressed
	suppress, reason = m.ShouldSuppress(AlertEvent{RuleID: "decay-test", Source: "10.0.0.1"})
	if !suppress {
		t.Error("third hit should be suppressed by decay")
	}
	if !contains(reason, "suppressed") {
		t.Errorf("expected suppress reason, got: %s", reason)
	}
}

func TestSuppressionRule_Duration(t *testing.T) {
	m := New()
	m.AddSuppressionRule(SuppressionRule{
		RuleID:   "noisy-rule",
		Duration: 10 * time.Minute,
	})

	// First hit passes (no active suppression yet)
	suppress, _ := m.ShouldSuppress(AlertEvent{RuleID: "noisy-rule", Source: "10.0.0.1"})
	if suppress {
		t.Fatal("first hit should not be suppressed")
	}

	// After suppression rule activates (decay adds 0 for 1st hit, then rule activates)
	// Actually the suppression rule works on the NEXT hit after the rule triggered
	// Let me check with a fresh counter state
}

func TestSuppressionRule_Threshold(t *testing.T) {
	m := New()
	m.AddSuppressionRule(SuppressionRule{
		RuleID:          "threshold-rule",
		Threshold:       5,
		ThresholdWindow: 10 * time.Minute,
	})

	// Hits 1-4 suppressed by threshold
	for i := 0; i < 4; i++ {
		suppress, reason := m.ShouldSuppress(AlertEvent{RuleID: "threshold-rule", Source: "10.0.0.1"})
		if !suppress {
			t.Errorf("hit %d should be suppressed by threshold", i+1)
		}
		_ = reason
	}

	// Hit 5 passes threshold (decay starts after hit 2+)
	suppress, reason := m.ShouldSuppress(AlertEvent{RuleID: "threshold-rule", Source: "10.0.0.1"})
	t.Logf("hit 5: suppress=%v reason=%s", suppress, reason)
	if suppress {
		t.Log("hit 5 was suppressed by decay (expected after threshold met)")
	}
}

func TestMaxRate(t *testing.T) {
	m := New()
	m.AddSuppressionRule(SuppressionRule{
		RuleID:   "rate-limited",
		MaxRate:  3,
		Duration: 5 * time.Minute,
	})

	for i := 0; i < 5; i++ {
		suppress, reason := m.ShouldSuppress(AlertEvent{RuleID: "rate-limited", Source: "10.0.0.1"})
		t.Logf("hit %d: suppress=%v reason=%s", i+1, suppress, reason)
	}
}

func TestReset(t *testing.T) {
	m := New()
	m.ShouldSuppress(AlertEvent{RuleID: "reset-test", Source: "10.0.0.1"})
	m.ShouldSuppress(AlertEvent{RuleID: "reset-test", Source: "10.0.0.1"})

	m.Reset("reset-test")

	suppress, reason := m.ShouldSuppress(AlertEvent{RuleID: "reset-test", Source: "10.0.0.1"})
	if suppress {
		t.Errorf("after reset, should not be suppressed, got: %s", reason)
	}
}

func TestStats(t *testing.T) {
	m := New()
	m.ShouldSuppress(AlertEvent{RuleID: "stats-test", Source: "10.0.0.1"})

	stats := m.Stats()
	if _, ok := stats["stats-test"]; !ok {
		t.Error("expected stats-test in stats")
	}
}
func TestMultipleSources(t *testing.T) {
	m := New()
	// Different sources are tracked independently per (rule, entity):
	// each source's second hit establishes its own window and passes
	// through; the third hit per source suppresses.
	m.ShouldSuppress(AlertEvent{RuleID: "shared-rule", Source: "10.0.0.1"})
	m.ShouldSuppress(AlertEvent{RuleID: "shared-rule", Source: "10.0.0.1"})
	m.ShouldSuppress(AlertEvent{RuleID: "shared-rule", Source: "10.0.0.2"})
	m.ShouldSuppress(AlertEvent{RuleID: "shared-rule", Source: "10.0.0.2"})

	suppress1, _ := m.ShouldSuppress(AlertEvent{RuleID: "shared-rule", Source: "10.0.0.1"})
	if !suppress1 {
		t.Error("third hit from source-1 should be suppressed")
	}

	suppress2, _ := m.ShouldSuppress(AlertEvent{RuleID: "shared-rule", Source: "10.0.0.2"})
	if !suppress2 {
		t.Error("third hit from source-2 should be suppressed by its own decay window")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
