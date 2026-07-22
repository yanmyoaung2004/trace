package monitor

import (
	"os"
	"strconv"
	"sync"
	"time"
)

type KillChainStep struct {
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Detail    string    `json:"detail,omitempty"`
	PID       int       `json:"pid"`
}

type KillChain struct {
	PID        int             `json:"pid"`
	Name       string          `json:"name"`
	Steps      []KillChainStep `json:"steps"`
	Confidence float64         `json:"confidence"`
	StartedAt  time.Time       `json:"started_at"`
	alerted    bool
	linkedPID  int
}

type KillChainReconstructor struct {
	eventCh    chan<- *Event
	chains     map[int]*KillChain
	byDetail   map[string][]int
	mu         sync.Mutex
	window     time.Duration
}

func NewKillChainReconstructor(eventCh chan<- *Event) *KillChainReconstructor {
	window := 5 * time.Minute
	if v := os.Getenv("TRACE_KILLCHAIN_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			window = d
		}
	}
	return &KillChainReconstructor{
		eventCh:  eventCh,
		chains:   make(map[int]*KillChain),
		byDetail: make(map[string][]int),
		window:   window,
	}
}

func (kc *KillChainReconstructor) Ingest(evt *Event) {
	if evt.Process == nil || evt.Process.PID == 0 {
		return
	}
	kc.mu.Lock()
	defer kc.mu.Unlock()

	pid := evt.Process.PID
	now := evt.Timestamp

	chain, exists := kc.chains[pid]
	if !exists || now.After(chain.StartedAt.Add(kc.window)) {
		chain = &KillChain{
			PID: pid, Name: evt.Process.Name, StartedAt: now,
		}
		kc.chains[pid] = chain
	}

	detail := ""
	if evt.File != nil {
		detail = evt.File.Path
	} else if evt.Network != nil {
		detail = evt.Network.RemoteIP
	} else if evt.Process != nil {
		detail = evt.Process.CmdLine
	}

	step := KillChainStep{
		Type: evt.Type, Timestamp: now,
		Detail: detail, PID: pid,
	}
	chain.Steps = append(chain.Steps, step)

	if detail != "" {
		kc.byDetail[detail] = append(kc.byDetail[detail], pid)
	}

	kc.evaluate(chain)
}

func (kc *KillChainReconstructor) evaluate(chain *KillChain) {
	if chain.alerted || len(chain.Steps) < 3 {
		return
	}

	hasCreate, hasProc, hasNet := false, false, false
	for _, s := range chain.Steps {
		switch s.Type {
		case EventFileCreate, EventFileModify:
			hasCreate = true
		case EventProcessCreate:
			hasProc = true
		case EventNetConnect:
			hasNet = true
		}
	}

	switch {
	case hasCreate && hasProc && hasNet:
		chain.Confidence = 0.75
	case hasCreate && hasProc:
		chain.Confidence = 0.5
	case hasProc && hasNet:
		chain.Confidence = 0.4
	default:
		return
	}

	ordered := true
	for i := 1; i < len(chain.Steps); i++ {
		if chain.Steps[i].Timestamp.Before(chain.Steps[i-1].Timestamp) {
			ordered = false
			break
		}
	}
	if ordered {
		chain.Confidence += 0.1
	}

	// Cross-process linking: check if this PID shares details with another PID
	for _, step := range chain.Steps {
		if step.Detail == "" {
			continue
		}
		if pids, ok := kc.byDetail[step.Detail]; ok {
			for _, otherPID := range pids {
				if otherPID != chain.PID {
					if otherChain, ok := kc.chains[otherPID]; ok && !otherChain.alerted {
						chain.Confidence += 0.15
						chain.linkedPID = otherPID
					}
				}
			}
		}
	}

	if chain.Confidence > 1.0 {
		chain.Confidence = 1.0
	}

	chain.alerted = true
	alert := &Event{
		Timestamp: time.Now(), Type: EventAlert,
		Severity: SeverityWarning,
		Process:  &ProcessInfo{PID: chain.PID, Name: chain.Name},
		Annotations: map[string]string{
			"correlation": "kill_chain",
			"confidence":  fmtInt(int(chain.Confidence * 100)),
			"steps":       fmtInt(len(chain.Steps)),
			"window":      kc.window.String(),
			"linked_pid":  fmtInt(chain.linkedPID),
		},
	}
	select {
	case kc.eventCh <- alert:
	default:
	}
}

func fmtInt(i int) string {
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
	return r
}

var _ = strconv.Itoa
