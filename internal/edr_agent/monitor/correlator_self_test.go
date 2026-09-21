package monitor_test

import (
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/edr_agent/monitor"
)

func fireRule(t *testing.T, rule *monitor.CorrRule, evtType monitor.EventType, n int) []*monitor.Event {
	t.Helper()
	ch := make(chan *monitor.Event, 64)
	c := monitor.NewCorrelator(ch)
	c.LoadTestRules([]*monitor.CorrRule{rule})
	base := time.Now()
	for i := range n {
		c.Ingestion(&monitor.Event{
			ID:        "evt",
			Timestamp: base.Add(time.Duration(i) * 10 * time.Millisecond),
			Type:      evtType,
			Severity:  monitor.SeverityInfo,
		})
	}
	var out []*monitor.Event
	for {
		select {
		case e := <-ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

func TestEachDefaultRuleFires(t *testing.T) {
	for _, r := range monitor.DefaultCorrRulesForTest() {
		var evtType monitor.EventType
		switch r.Name {
		case "process_burst", "suspicious_children":
			evtType = monitor.EventProcessCreate
		case "rapid_deletion":
			evtType = monitor.EventFileDelete
		case "connection_burst":
			evtType = monitor.EventNetConnect
		default:
			t.Fatalf("unknown default rule %q", r.Name)
		}
		got := fireRule(t, r, evtType, r.Threshold)
		if len(got) == 0 {
			t.Errorf("rule %s did not fire at threshold %d", r.Name, r.Threshold)
		}
	}
}

func TestMatchAllRuleFires(t *testing.T) {
	r := &monitor.CorrRule{Name: "match-all", Window: time.Second, Threshold: 2, Severity: monitor.SeverityWarning}
	if got := fireRule(t, r, monitor.EventFileCreate, 2); len(got) == 0 {
		t.Error("empty EventTypes must match-all")
	}
}

func TestThresholdOneFiresImmediately(t *testing.T) {
	r := &monitor.CorrRule{Name: "t1", Window: time.Second, Threshold: 1, Severity: monitor.SeverityWarning}
	if got := fireRule(t, r, monitor.EventProcessCreate, 1); len(got) == 0 {
		t.Error("threshold=1 must fire on first event")
	}
}
