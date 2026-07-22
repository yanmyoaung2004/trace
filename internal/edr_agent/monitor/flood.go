package monitor

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

type FloodDetector struct {
	eventCh    chan<- *Event
	counts     map[EventType]*windowCounter
	mu         sync.Mutex
	floodMode  bool
	threshold  int
	window     time.Duration
}

type windowCounter struct {
	events  []time.Time
}

func NewFloodDetector(eventCh chan<- *Event) *FloodDetector {
	return &FloodDetector{
		eventCh:   eventCh,
		counts:    make(map[EventType]*windowCounter),
		threshold: 100,
		window:    time.Second,
	}
}

func (fd *FloodDetector) Ingest(evt *Event) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	wc, exists := fd.counts[evt.Type]
	if !exists {
		wc = &windowCounter{}
		fd.counts[evt.Type] = wc
	}

	now := time.Now()
	cutoff := now.Add(-fd.window)

	var active []time.Time
	for _, t := range wc.events {
		if t.After(cutoff) {
			active = append(active, t)
		}
	}
	active = append(active, now)
	wc.events = active

	if len(active) > fd.threshold && !fd.floodMode {
		fd.floodMode = true
		fd.emitFloodAlert(evt.Type, len(active))
		go fd.clearAfter(fd.window * 3)
	}
}

func (fd *FloodDetector) clearAfter(d time.Duration) {
	time.Sleep(d)
	fd.mu.Lock()
	fd.floodMode = false
	fd.counts = make(map[EventType]*windowCounter)
	fd.mu.Unlock()
}

func (fd *FloodDetector) IsFlooding() bool {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	return fd.floodMode
}

func (fd *FloodDetector) emitFloodAlert(etype EventType, count int) {
	alert := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      EventAlert,
		Severity:  SeverityWarning,
		Annotations: map[string]string{
			"correlation": "event_flood",
			"event_type":  string(etype),
			"count":       itoa(count),
			"window_ms":   itoa(int(fd.window.Milliseconds())),
		},
	}
	select {
	case fd.eventCh <- alert:
	default:
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	r := ""
	n := i
	if n < 0 {
		n = -n
	}
	for n > 0 {
		r = string(rune('0'+n%10)) + r
		n /= 10
	}
	if i < 0 {
		r = "-" + r
	}
	return r
}
