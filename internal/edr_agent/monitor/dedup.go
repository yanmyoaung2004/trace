package monitor

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

type Deduplicator struct {
	mu        sync.Mutex
	keys      map[string]time.Time
	ttl       time.Duration
	maxSize   int
	hitCount  int64
	missCount int64
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		keys:    make(map[string]time.Time),
		ttl:     30 * time.Second,
		maxSize: 5000,
	}
}

func (d *Deduplicator) IsDuplicate(evt *Event) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := d.eventKey(evt)
	now := time.Now()

	if _, exists := d.keys[key]; exists {
		d.hitCount++
		return true
	}

	d.keys[key] = now
	d.missCount++

	if len(d.keys) > d.maxSize {
		d.evictLocked(now)
	}

	return false
}

func (d *Deduplicator) eventKey(evt *Event) string {
	switch {
	case evt.Process != nil && evt.Process.PID > 0:
		return fmt.Sprintf("proc:%d:%s", evt.Process.PID, evt.Type)
	case evt.File != nil && evt.File.Path != "":
		h := sha256.Sum256([]byte(evt.File.Path + string(evt.Type)))
		return fmt.Sprintf("file:%x", h[:8])
	case evt.Network != nil:
		return fmt.Sprintf("net:%s:%d:%s", evt.Network.LocalIP, evt.Network.LocalPort, evt.Type)
	default:
		return fmt.Sprintf("evt:%d", evt.Timestamp.UnixNano())
	}
}

func (d *Deduplicator) evictLocked(now time.Time) {
	cutoff := now.Add(-d.ttl)
	for k, v := range d.keys {
		if v.Before(cutoff) {
			delete(d.keys, k)
		}
		if len(d.keys) <= d.maxSize/2 {
			break
		}
	}
}

func (d *Deduplicator) Stats() (int64, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hitCount, d.missCount
}

func (d *Deduplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.keys = make(map[string]time.Time)
	d.hitCount = 0
	d.missCount = 0
}
