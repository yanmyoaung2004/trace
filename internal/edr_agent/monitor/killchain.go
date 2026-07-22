package monitor

import (
	"sync"
	"time"
)

type KillChainStep struct {
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Detail    string    `json:"detail,omitempty"`
}

type KillChain struct {
	AgentID    string          `json:"agent_id"`
	PID        int             `json:"pid"`
	Steps      []KillChainStep `json:"steps"`
	Confidence float64         `json:"confidence"`
	StartedAt  time.Time       `json:"started_at"`
	alerted    bool
}

type KillChainReconstructor struct {
	eventCh   chan<- *Event
	chains    map[int]*KillChain
	mu        sync.Mutex
	window    time.Duration
}

func NewKillChainReconstructor(eventCh chan<- *Event) *KillChainReconstructor {
	return &KillChainReconstructor{
		eventCh: eventCh,
		chains:  make(map[int]*KillChain),
		window:  30 * time.Second,
	}
}

func (kc *KillChainReconstructor) Ingest(evt *Event) {
	if evt.Process == nil || evt.Process.PID == 0 {
		return
	}

	kc.mu.Lock()
	defer kc.mu.Unlock()

	pid := evt.Process.PID
	chain, exists := kc.chains[pid]
	if !exists {
		chain = &KillChain{
			PID:       pid,
			StartedAt: evt.Timestamp,
		}
		kc.chains[pid] = chain
	}

	if evt.Timestamp.After(chain.StartedAt.Add(kc.window)) {
		delete(kc.chains, pid)
		return
	}

	step := KillChainStep{
		Type:      evt.Type,
		Timestamp: evt.Timestamp,
	}
	if evt.File != nil {
		step.Detail = evt.File.Path
	} else if evt.Network != nil {
		step.Detail = evt.Network.RemoteIP
	} else if evt.Process != nil {
		step.Detail = evt.Process.Name
	}

	chain.Steps = append(chain.Steps, step)
	kc.evaluate(chain)
}

func (kc *KillChainReconstructor) evaluate(chain *KillChain) {
	if chain.alerted || len(chain.Steps) < 3 {
		return
	}

	// Look for file_create → process_create → net_connect
	hasCreate := false
	hasProc := false
	hasNet := false

	for _, s := range chain.Steps {
		if s.Type == EventFileCreate || s.Type == EventFileModify {
			hasCreate = true
		}
		if s.Type == EventProcessCreate {
			hasProc = true
		}
		if s.Type == EventNetConnect {
			hasNet = true
		}
	}

	if hasCreate && hasProc && hasNet {
		chain.Confidence = 0.75
	} else if hasCreate && hasProc {
		chain.Confidence = 0.5
	} else if hasProc && hasNet {
		chain.Confidence = 0.4
	} else {
		return
	}

	// Check if steps are in temporal order
	ordered := true
	for i := 1; i < len(chain.Steps); i++ {
		if chain.Steps[i].Timestamp.Before(chain.Steps[i-1].Timestamp) {
			ordered = false
			break
		}
	}
	if ordered && chain.Confidence > 0 {
		chain.Confidence += 0.1
	}
	if chain.Confidence > 1.0 {
		chain.Confidence = 1.0
	}

	chain.alerted = true
	alert := &Event{
		ID:        "",
		Timestamp: time.Now(),
		Type:      EventAlert,
		Severity:  SeverityWarning,
		Process:   &ProcessInfo{PID: chain.PID},
		Annotations: map[string]string{
			"correlation": "kill_chain",
			"confidence":  itoa2(int(chain.Confidence * 100)),
			"steps":       itoa2(len(chain.Steps)),
			"window_ms":   itoa2(int(kc.window.Milliseconds())),
		},
	}
	select {
	case kc.eventCh <- alert:
	default:
	}
}

func itoa2(i int) string {
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
