package monitor

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type FPCounter struct {
	RuleName    string    `json:"rule_name"`
	ProcessName string    `json:"process_name"`
	Count       int       `json:"count"`
	LastSeen    time.Time `json:"last_seen"`
	Throttled   bool      `json:"throttled"`
}

type FPLearning struct {
	mu         sync.Mutex
	counters   map[string]*FPCounter
	dataDir    string
	threshold  int
	suppressMs int64
}

func NewFPLearning(dataDir string) *FPLearning {
	fp := &FPLearning{
		counters:   make(map[string]*FPCounter),
		dataDir:    dataDir,
		threshold:  10,
		suppressMs: 300000,
	}
	if dataDir != "" {
		fp.load()
	}
	return fp
}

func (fp *FPLearning) Record(ruleName, processName string) bool {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	key := ruleName + ":" + processName
	c, exists := fp.counters[key]
	if !exists {
		c = &FPCounter{RuleName: ruleName, ProcessName: processName}
		fp.counters[key] = c
	}

	c.Count++
	c.LastSeen = time.Now()

	if c.Count >= fp.threshold && !c.Throttled {
		c.Throttled = true
		log.Printf("[fplearn] throttling %s on %s (dismissed %d times)", ruleName, processName, c.Count)
		fp.save()
	}

	return c.Throttled
}

func (fp *FPLearning) IsThrottled(ruleName, processName string) bool {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	key := ruleName + ":" + processName
	c, exists := fp.counters[key]
	if !exists || !c.Throttled {
		return false
	}

	if time.Since(c.LastSeen) > time.Duration(fp.suppressMs)*time.Millisecond {
		c.Throttled = false
		c.Count = 0
		return false
	}

	return true
}

func (fp *FPLearning) Dismiss(ruleName, processName string) {
	fp.Record(ruleName, processName)
}

func (fp *FPLearning) save() {
	if fp.dataDir == "" {
		return
	}
	fp.mu.Lock()
	counters := make([]*FPCounter, 0, len(fp.counters))
	for _, c := range fp.counters {
		counters = append(counters, c)
	}
	fp.mu.Unlock()

	data, err := json.MarshalIndent(counters, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(fp.dataDir, 0700)
	os.WriteFile(filepath.Join(fp.dataDir, "fp_counters.json"), data, 0600)
}

func (fp *FPLearning) load() {
	if fp.dataDir == "" {
		return
	}
	path := filepath.Join(fp.dataDir, "fp_counters.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var counters []*FPCounter
	if err := json.Unmarshal(data, &counters); err != nil {
		return
	}
	fp.mu.Lock()
	defer fp.mu.Unlock()
	for _, c := range counters {
		fp.counters[c.RuleName+":"+c.ProcessName] = c
	}
}
