package monitor

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

type CorrRule struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Window      time.Duration `json:"window_ms"`
	Threshold   int           `json:"threshold"`
	EventTypes  []EventType   `json:"event_types"`
	Severity    Severity      `json:"severity"`
	SuppressMs  int64         `json:"suppress_ms"`
	MatchFn     string        `json:"match_fn,omitempty"`
}

type Correlator struct {
	eventCh    chan<- *Event
	buffer     []*Event
	bufferSize int
	mu         sync.Mutex
	rules      []*CorrRule
	suppress   map[string]time.Time
	done       chan struct{}
	created    map[string]*Event
	dataDir    string
}

func NewCorrelator(eventCh chan<- *Event) *Correlator {
	c := &Correlator{
		eventCh:    eventCh,
		buffer:     make([]*Event, 0, 2000),
		bufferSize: 2000,
		done:       make(chan struct{}),
		rules:      defaultCorrRules(),
		suppress:   make(map[string]time.Time),
		created:    make(map[string]*Event),
	}
	return c
}

func (c *Correlator) Start() { go c.trimLoop() }

func (c *Correlator) Stop() { close(c.done) }

func (c *Correlator) SetDataDir(dir string) { c.dataDir = dir }

func (c *Correlator) LoadRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var rules []*CorrRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("correlator: invalid rule JSON: %w", err)
	}
	for i, r := range rules {
		if r.Name == "" {
			return fmt.Errorf("correlator: rule %d has no name", i)
		}
		if r.Window <= 0 {
			return fmt.Errorf("correlator: rule %q has invalid window: %v", r.Name, r.Window)
		}
		if r.Threshold <= 0 {
			return fmt.Errorf("correlator: rule %q has invalid threshold: %d", r.Name, r.Threshold)
		}
	}
	c.mu.Lock()
	c.rules = rules
	c.mu.Unlock()
	log.Printf("[correlator] loaded %d validated rules from %s", len(rules), path)
	return nil
}

func (c *Correlator) Reload(path string) error {
	log.Printf("[correlator] hot-reloading rules from %s", path)
	return c.LoadRules(path)
}

func (c *Correlator) Ingestion(evt *Event) {
	c.mu.Lock()

	c.buffer = append(c.buffer, evt)
	if len(c.buffer) > c.bufferSize {
		c.buffer = c.buffer[len(c.buffer)-c.bufferSize:]
	}

	// Track file creates for create_then_delete
	if evt.Type == EventFileCreate && evt.File != nil && evt.File.Path != "" {
		c.created[evt.File.Path] = evt
	}
	if evt.Type == EventFileDelete && evt.File != nil && evt.File.Path != "" {
		if createEvt, ok := c.created[evt.File.Path]; ok {
			if time.Since(createEvt.Timestamp) < 5*time.Second {
				c.emitLocked(&Event{
					ID: uuid.New().String(), Timestamp: time.Now(),
					Type: EventAlert, Severity: SeverityWarning,
					File: evt.File,
					Annotations: map[string]string{
						"correlation": "create_then_delete",
						"details":     fmt.Sprintf("%s created then deleted in <5s", evt.File.Path),
					},
				})
			}
			delete(c.created, evt.File.Path)
		}
	}

	c.evaluateLocked(evt)
	c.mu.Unlock()
}

func (c *Correlator) evaluateLocked(newEvt *Event) {
	for _, rule := range c.rules {
		if !c.matchesType(rule, newEvt) {
			continue
		}

		// Suppression check
		supKey := fmt.Sprintf("%s:%s", rule.Name, c.eventKey(newEvt))
		if lastTime, ok := c.suppress[supKey]; ok {
			if time.Since(lastTime) < time.Duration(rule.SuppressMs)*time.Millisecond {
				continue
			}
		}

		window := c.windowEventsLocked(rule, newEvt.Timestamp)
		if len(window) < rule.Threshold {
			continue
		}

		scored := len(window) * int(rule.Severity) / rule.Threshold
		if scored < 3 {
			continue
		}

		c.suppress[supKey] = time.Now()

		c.emitLocked(&Event{
			ID: uuid.New().String(), Timestamp: time.Now(),
			Type: EventAlert, Severity: rule.Severity,
			Annotations: map[string]string{
				"correlation": rule.Name,
				"description": rule.Description,
				"count":       fmt.Sprintf("%d", len(window)),
				"score":       fmt.Sprintf("%d", scored),
			},
		})
	}
}

func (c *Correlator) eventKey(evt *Event) string {
	switch {
	case evt.Process != nil:
		return fmt.Sprintf("pid:%d", evt.Process.PID)
	case evt.File != nil:
		h := sha256.Sum256([]byte(evt.File.Path))
		return fmt.Sprintf("file:%x", h[:4])
	case evt.Network != nil:
		return fmt.Sprintf("net:%s:%d", evt.Network.RemoteIP, evt.Network.RemotePort)
	default:
		return fmt.Sprintf("evt:%d", evt.Timestamp.UnixNano())
	}
}

func (c *Correlator) matchesType(rule *CorrRule, evt *Event) bool {
	for _, t := range rule.EventTypes {
		if evt.Type == t {
			return true
		}
	}
	return false
}

func (c *Correlator) windowEventsLocked(rule *CorrRule, t time.Time) []*Event {
	start := t.Add(-rule.Window)
	var result []*Event
	for _, evt := range c.buffer {
		if evt.Timestamp.After(start) && evt.Timestamp.Before(t) || evt.Timestamp.Equal(t) {
			if c.matchesType(rule, evt) {
				result = append(result, evt)
			}
		}
	}
	return result
}

func (c *Correlator) emitLocked(evt *Event) {
	select {
	case c.eventCh <- evt:
	default:
	}
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

	for path, evt := range c.created {
		if time.Since(evt.Timestamp) > 10*time.Second {
			delete(c.created, path)
		}
	}
}

func defaultCorrRules() []*CorrRule {
	return []*CorrRule{
		{Name: "process_burst", Description: "Process creation burst", Window: 5 * time.Second, Threshold: 20, Severity: SeverityWarning, SuppressMs: 30000},
		{Name: "rapid_deletion", Description: "Rapid file deletion", Window: 10 * time.Second, Threshold: 50, Severity: SeverityWarning, SuppressMs: 60000},
		{Name: "suspicious_children", Description: "Suspicious child process burst", Window: 30 * time.Second, Threshold: 3, Severity: SeverityAlert, SuppressMs: 120000},
		{Name: "connection_burst", Description: "Outbound connection burst", Window: 10 * time.Second, Threshold: 15, Severity: SeverityWarning, SuppressMs: 30000},
	}
}
