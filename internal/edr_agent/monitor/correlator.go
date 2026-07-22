package monitor

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type CorrelationRule struct {
	Name        string
	Description string
	Window      time.Duration
	Threshold   int
	EventTypes  []EventType
	Severity    Severity
	MatchFn     func(events []*Event) bool
}

type Correlator struct {
	eventCh    chan<- *Event
	buffer     []*Event
	bufferSize int
	mu         sync.Mutex
	rules      []*CorrelationRule
	done       chan struct{}
}

func NewCorrelator(eventCh chan<- *Event) *Correlator {
	c := &Correlator{
		eventCh:    eventCh,
		buffer:     make([]*Event, 0, 1000),
		bufferSize: 1000,
		done:       make(chan struct{}),
	}
	c.rules = c.defaultRules()
	return c
}

func (c *Correlator) Start() {
	go c.trimLoop()
}

func (c *Correlator) Stop() {
	close(c.done)
}

func (c *Correlator) Ingestion(evt *Event) {
	c.mu.Lock()
	c.buffer = append(c.buffer, evt)
	if len(c.buffer) > c.bufferSize {
		c.buffer = c.buffer[len(c.buffer)-c.bufferSize:]
	}
	c.mu.Unlock()

	c.evaluate(evt)
}

func (c *Correlator) trimLoop() {
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-tick.C:
			c.trim()
		}
	}
}

func (c *Correlator) trim() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	var kept []*Event
	for _, evt := range c.buffer {
		if evt.Timestamp.After(cutoff) {
			kept = append(kept, evt)
		}
	}
	c.buffer = kept
}

func (c *Correlator) evaluate(newEvt *Event) {
	for _, rule := range c.rules {
		if !c.matchesType(rule, newEvt) {
			continue
		}

		window := c.windowEvents(rule, newEvt.Timestamp)
		if len(window) < rule.Threshold {
			continue
		}

		if rule.MatchFn != nil && !rule.MatchFn(window) {
			continue
		}

		c.emitAlert(rule, window)
	}
}

func (c *Correlator) matchesType(rule *CorrelationRule, evt *Event) bool {
	for _, t := range rule.EventTypes {
		if evt.Type == t {
			return true
		}
	}
	return false
}

func (c *Correlator) windowEvents(rule *CorrelationRule, t time.Time) []*Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	start := t.Add(-rule.Window)
	var result []*Event
	for _, evt := range c.buffer {
		if evt.Timestamp.After(start) && evt.Timestamp.Before(t) {
			for _, et := range rule.EventTypes {
				if evt.Type == et {
					result = append(result, evt)
					break
				}
			}
		}
	}
	return result
}

func (c *Correlator) emitAlert(rule *CorrelationRule, matched []*Event) {
	details := make([]string, 0, len(matched))
	for _, evt := range matched {
		details = append(details, fmt.Sprintf("%s/%d", evt.Process.Name, evt.Process.PID))
	}

	alert := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      EventAlert,
		Severity:  rule.Severity,
		Annotations: map[string]string{
			"correlation": rule.Name,
			"description": rule.Description,
			"count":       fmt.Sprintf("%d", len(matched)),
			"details":     strings.Join(details, ","),
		},
	}

	select {
	case c.eventCh <- alert:
	default:
	}
}

func (c *Correlator) defaultRules() []*CorrelationRule {
	return []*CorrelationRule{
		{
			Name: "process_burst", Description: "Multiple process creation events in short window",
			Window: 5 * time.Second, Threshold: 20, Severity: SeverityWarning,
			EventTypes: []EventType{EventProcessCreate},
			MatchFn:    nil,
		},
		{
			Name: "rapid_fire_deletion", Description: "Multiple file deletions in rapid succession",
			Window: 10 * time.Second, Threshold: 50, Severity: SeverityWarning,
			EventTypes: []EventType{EventFileDelete},
		},
		{
			Name: "suspicious_children_burst", Description: "Multiple suspicious child processes",
			Window: 30 * time.Second, Threshold: 3, Severity: SeverityAlert,
			EventTypes: []EventType{EventProcessCreate},
			MatchFn:    func(events []*Event) bool {
				suspicious := 0
				for _, e := range events {
					if e.Severity >= SeverityWarning {
						suspicious++
					}
				}
				return suspicious >= 3
			},
		},
		{
			Name: "connection_burst", Description: "Multiple outbound connections to different IPs",
			Window: 10 * time.Second, Threshold: 15, Severity: SeverityWarning,
			EventTypes: []EventType{EventNetConnect},
		},
		{
			Name: "create_then_delete", Description: "File created then rapidly deleted",
			Window: 5 * time.Second, Threshold: 1, Severity: SeverityWarning,
			EventTypes: []EventType{EventFileCreate},
			MatchFn: func(events []*Event) bool {
				return false
			},
		},
	}
}
