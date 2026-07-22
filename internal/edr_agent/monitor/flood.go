package monitor

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	minThreshold  = 20
	maxThreshold  = 5000
	defaultThreshold = 100
)

type windowCounter struct {
	events  []time.Time
}

type FloodDetector struct {
	eventCh       chan<- *Event
	counts        map[EventType]*windowCounter
	mu            sync.Mutex
	floodMode     bool
	window        time.Duration
	baseline      map[EventType]int
	warmupCount   map[EventType]int
	warmupPeriod  time.Time
	threshold     map[EventType]int
}

func NewFloodDetector(eventCh chan<- *Event) *FloodDetector {
	return &FloodDetector{
		eventCh:      eventCh,
		counts:       make(map[EventType]*windowCounter),
		window:       time.Second,
		baseline:     make(map[EventType]int),
		warmupCount:  make(map[EventType]int),
		warmupPeriod: time.Now(),
		threshold:    make(map[EventType]int),
	}
}

func (fd *FloodDetector) Ingest(evt *Event) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	// Warmup: first 60 seconds, count events to establish baseline
	if time.Since(fd.warmupPeriod) < 60*time.Second {
		fd.warmupCount[evt.Type]++
		return
	}

	// At 60s, calculate baseline thresholds
	if len(fd.baseline) == 0 && time.Since(fd.warmupPeriod) >= 60*time.Second {
		for etype, count := range fd.warmupCount {
			avg := count / 60
			t := avg * 3 // threshold = 3x average
			if t < minThreshold {
				t = minThreshold
			}
			if t > maxThreshold {
				t = maxThreshold
			}
			fd.threshold[etype] = t
		}
		fd.warmupCount = nil
	}

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

	t := fd.threshold[evt.Type]
	if t == 0 {
		t = defaultThreshold
	}

	if len(active) > t && !fd.floodMode {
		fd.floodMode = true
		fd.emitFloodAlert(evt.Type, len(active), t)
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

func (fd *FloodDetector) emitFloodAlert(etype EventType, count int, threshold int) {
	alert := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      EventAlert,
		Severity:  SeverityWarning,
		Annotations: map[string]string{
			"correlation": "event_flood",
			"event_type":  string(etype),
			"count":       itoa(count),
			"threshold":   itoa(threshold),
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
