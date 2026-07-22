package edr_agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/edr_agent/monitor"
	"github.com/yanmyoaung2004/trace/internal/edr_agent/queue"
	"github.com/yanmyoaung2004/trace/internal/edr_agent/response"
	"github.com/yanmyoaung2004/trace/internal/edr_agent/transport"
)

type Agent struct {
	config *Config
	client *transport.Client

	agentID    string
	hostname   string
	startedAt  time.Time

	eventCh    chan *monitor.Event
	done       chan struct{}
	mu         sync.Mutex
	running    bool

	procMon    *monitor.ProcessMonitor
	linuxProcMon *monitor.LinuxProcMonitor
	winProcMon   *monitor.WindowsProcMonitor
	fileMon    *monitor.FileMonitor
	netMon     *monitor.NetworkMonitor
	exec       *response.Executor
	eventQueue *queue.EventQueue

	yara       *monitor.YaraMatcher
	scanCache  *monitor.ScanCache
	scanWorkers chan struct{}
	procTree   *monitor.ProcessTree
	correlator *monitor.Correlator
	dedup      *monitor.Deduplicator

	stats      AgentStats
}

type AgentStats struct {
	EventsCollected   int64     `json:"events_collected"`
	EventsSent        int64     `json:"events_sent"`
	EventsFailed      int64     `json:"events_failed"`
	ActionsExecuted   int64     `json:"actions_executed"`
	ActionsFailed     int64     `json:"actions_failed"`
	HeartbeatsSent    int64     `json:"heartbeats_sent"`
	Reconnections     int64     `json:"reconnections"`
	LastError         string    `json:"last_error,omitempty"`
	LastErrorTime     time.Time `json:"last_error_time,omitempty"`
	UptimeSeconds     int64     `json:"uptime_seconds"`
}

func New(cfg *Config) *Agent {
	hostname, _ := os.Hostname()
	if cfg.Hostname != "" {
		hostname = cfg.Hostname
	}

	eventCh := make(chan *monitor.Event, cfg.EventQueueSize)

	client := transport.NewClient(&transport.Config{
		ServerURL:    cfg.ServerURL,
		APIKey:       cfg.APIKey,
		AgentID:      cfg.AgentID,
		TLSCertFile:  cfg.TLSCertFile,
		TLSKeyFile:   cfg.TLSKeyFile,
		CAFile:       cfg.CAFile,
		Timeout:      30 * time.Second,
		RetryMax:     5,
		RetryBase:    time.Second,
	})

	exec := response.NewExecutor(eventCh)

	a := &Agent{
		config:   cfg,
		client:   client,
		hostname: hostname,
		eventCh:  eventCh,
		done:     make(chan struct{}),
		exec:     exec,
		yara:     monitor.NewYaraMatcher(),
		procTree: monitor.NewProcessTree(filepath.Join(cfg.DataDir, "tree")),
		dedup:    monitor.NewDeduplicator(filepath.Join(cfg.DataDir, "dedup")),
	}

	if cfg.AgentID != "" {
		a.agentID = cfg.AgentID
	}

	return a
}

func (a *Agent) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("agent already running")
	}
	a.running = true
	a.startedAt = time.Now()
	a.mu.Unlock()

	log.Printf("[trace-agent] starting v0.1.1 on %s/%s", runtime.GOOS, runtime.GOARCH)
	log.Printf("[trace-agent] server: %s", a.config.ServerURL)
	log.Printf("[trace-agent] hostname: %s", a.hostname)

	if err := a.register(ctx); err != nil {
		return fmt.Errorf("register: %w", err)
	}

	if a.config.MonitorProcess {
		switch runtime.GOOS {
		case "linux":
			lpm := monitor.NewLinuxProcMonitor(a.eventCh)
			if err := lpm.Start(ctx); err == nil {
				log.Printf("[trace-agent] linux netlink process monitor active")
			} else {
				a.procMon = monitor.NewProcessMonitor(a.eventCh)
				a.procMon.Start(ctx)
				log.Printf("[trace-agent] /proc polling fallback active")
			}
		case "windows":
			wpm := monitor.NewWindowsProcMonitor(a.eventCh)
			if err := wpm.Start(ctx); err == nil {
				log.Printf("[trace-agent] windows ETW process monitor active")
			} else {
				a.procMon = monitor.NewProcessMonitor(a.eventCh)
				a.procMon.Start(ctx)
				log.Printf("[trace-agent] WMI polling fallback active")
			}
		default:
			a.procMon = monitor.NewProcessMonitor(a.eventCh)
			a.procMon.Start(ctx)
		}
	}
	if a.config.MonitorFile {
		a.fileMon = monitor.NewFileMonitor(a.eventCh, a.config.WatchPaths, a.config.ExcludePaths)
		if err := a.fileMon.Start(ctx); err != nil {
			log.Printf("[trace-agent] file monitor: %v (disabled)", err)
		}
	}
	if a.config.MonitorNetwork {
		a.netMon = monitor.NewNetworkMonitor(a.eventCh, 30*time.Second)
		if err := a.netMon.Start(ctx); err != nil {
			log.Printf("[trace-agent] network monitor: %v (disabled)", err)
		}
	}

	go a.loop(ctx)
	go a.batcher(ctx)
	go a.actionPoller(ctx)

	eq, err := queue.New(filepath.Join(a.config.DataDir, "queue"), a.config.EventQueueSize)
	if err != nil {
		log.Printf("[trace-agent] event queue: %v (running without disk buffer)", err)
	} else {
		a.eventQueue = eq
		log.Printf("[trace-agent] event queue ready (%s, max %d)", eq.Path(), a.config.EventQueueSize)
	}

	a.correlator = monitor.NewCorrelator(a.eventCh)
	a.correlator.Start()
	a.scanCache = monitor.NewScanCache()
	a.scanWorkers = make(chan struct{}, 8)

	go a.analysisLoop(ctx)

	log.Printf("[trace-agent] agent started (id: %s)", a.agentID)
	return nil
}

func (a *Agent) Stop(ctx context.Context) error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = false
	close(a.done)
	a.mu.Unlock()

	if a.linuxProcMon != nil {
		a.linuxProcMon.Stop()
	}
	if a.winProcMon != nil {
		a.winProcMon.Stop()
	}
	if a.procMon != nil {
		a.procMon.Stop()
	}
	if a.fileMon != nil {
		a.fileMon.Stop()
	}
	if a.netMon != nil {
		a.netMon.Stop()
	}
	if a.procTree != nil {
		a.procTree.Close()
	}
	if a.dedup != nil {
		a.dedup.Close()
	}
	if a.eventQueue != nil {
		a.eventQueue.Close()
	}

	log.Printf("[trace-agent] agent stopped")
	return nil
}

func (a *Agent) register(ctx context.Context) error {
	if a.agentID != "" {
		return nil
	}

	info, err := a.collectSystemInfo()
	if err != nil {
		return fmt.Errorf("collect system info: %w", err)
	}

	regReq := &transport.RegisterRequest{
		Hostname:      info.Hostname,
		Platform:      info.Platform,
		Arch:          info.Arch,
		Version:       info.Version,
		KernelVersion: info.KernelVersion,
		CPUCount:      info.CPUCount,
		MemoryMB:      info.MemoryMB,
		AgentVersion:  info.AgentVersion,
		Monitors:      info.Monitors,
	}

	resp, err := a.client.Register(ctx, regReq)
	if err != nil {
		return fmt.Errorf("server registration: %w", err)
	}

	a.agentID = resp.AgentID
	a.client.SetAgentID(resp.AgentID)

	cfgPath := filepath.Join(a.config.DataDir, "agent.json")
	meta := map[string]string{"agent_id": a.agentID}
	if data, err := json.Marshal(meta); err == nil {
		os.MkdirAll(a.config.DataDir, 0700)
		os.WriteFile(cfgPath, data, 0600)
	}

	log.Printf("[trace-agent] registered with server (id: %s)", a.agentID)
	return nil
}

type SystemInfo struct {
	Hostname      string `json:"hostname"`
	Platform      string `json:"platform"`
	Arch          string `json:"arch"`
	Version       string `json:"version"`
	KernelVersion string `json:"kernel_version,omitempty"`
	CPUCount      int    `json:"cpu_count"`
	MemoryMB      int64  `json:"memory_mb"`
	AgentVersion  string `json:"agent_version"`
	Monitors      string `json:"monitors"`
}

func (a *Agent) collectSystemInfo() (*SystemInfo, error) {
	info := &SystemInfo{
		Hostname:     a.hostname,
		Platform:     runtime.GOOS,
		Arch:         runtime.GOARCH,
		Version:      "0.1.1",
		CPUCount:     runtime.NumCPU(),
		AgentVersion: "0.1.1",
		Monitors:     fmt.Sprintf("process:%v,file:%v,net:%v", a.config.MonitorProcess, a.config.MonitorFile, a.config.MonitorNetwork),
	}

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			info.KernelVersion = string(data)
		}
		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			var total int64
			fmt.Sscanf(string(data), "MemTotal: %d kB", &total)
			info.MemoryMB = total / 1024
		}
	}

	return info, nil
}

func (a *Agent) loop(ctx context.Context) {
	heartbeatTick := time.NewTicker(a.config.HeartbeatInterval)
	defer heartbeatTick.Stop()

	for {
		select {
		case <-a.done:
			return
		case <-heartbeatTick.C:
			a.sendHeartbeat(ctx)
		}
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context) {
	info := &transport.Heartbeat{
		AgentID:  a.agentID,
		Hostname: a.hostname,
		Status:   "active",
		Version:  "0.1.1",
		Uptime:   int64(time.Since(a.startedAt).Seconds()),
		Stats: transport.AgentStats{
			EventsCollected: a.stats.EventsCollected,
			EventsSent:      a.stats.EventsSent,
			ActionsExecuted: a.stats.ActionsExecuted,
			ActionsFailed:   a.stats.ActionsFailed,
			CPUPercent:      a.getCPUUsage(),
			MemoryMB:        a.getMemoryUsage(),
		},
	}

	if err := a.client.Heartbeat(ctx, info); err != nil {
		log.Printf("[trace-agent] heartbeat failed: %v", err)
		a.stats.LastError = err.Error()
		a.stats.LastErrorTime = time.Now()
		a.stats.Reconnections++
		return
	}
	a.stats.HeartbeatsSent++
}

func (a *Agent) batcher(ctx context.Context) {
	batchTick := time.NewTicker(a.config.BatchInterval)
	defer batchTick.Stop()

	var batch []*monitor.Event
	rateLimiter := make(chan struct{}, a.config.MaxEventsPerSec)

	go func() {
		for {
			rateLimiter <- struct{}{}
			time.Sleep(time.Second / time.Duration(a.config.MaxEventsPerSec))
		}
	}()

	for {
		select {
		case <-a.done:
			if len(batch) > 0 {
				a.flushBatch(ctx, batch)
			}
			return
		case evt := <-a.eventCh:
			select {
			case <-rateLimiter:
				batch = append(batch, evt)
				a.stats.EventsCollected++
			default:
				log.Printf("[trace-agent] rate limit exceeded, dropping event")
			}
			if len(batch) >= a.config.MaxBatchSize {
				a.flushBatch(ctx, batch)
				batch = nil
			}
		case <-batchTick.C:
			if len(batch) > 0 {
				a.flushBatch(ctx, batch)
				batch = nil
			}
		}
	}
}

func (a *Agent) flushBatch(ctx context.Context, batch []*monitor.Event) {
	if len(batch) == 0 {
		return
	}

	if err := a.client.SendEvents(ctx, a.agentID, batch); err != nil {
		log.Printf("[trace-agent] event batch failed (%d events): %v", len(batch), err)
		a.stats.EventsFailed += int64(len(batch))

		// Buffer to disk queue for retry
		if a.eventQueue != nil {
			for _, evt := range batch {
				if err := a.eventQueue.Push(evt); err != nil {
					log.Printf("[trace-agent] queue push error: %v", err)
					break
				}
			}
			log.Printf("[trace-agent] queued %d events for retry (queue size: %d)", len(batch), a.eventQueue.Len())
		}
		return
	}

	a.stats.EventsSent += int64(len(batch))
}

func (a *Agent) analysisLoop(ctx context.Context) {
	ancestryTick := time.NewTicker(60 * time.Second)
	dedupStatsTick := time.NewTicker(5 * time.Minute)
	scanStatsTick := time.NewTicker(10 * time.Minute)
	defer ancestryTick.Stop()
	defer dedupStatsTick.Stop()
	defer scanStatsTick.Stop()

	for {
		select {
		case <-a.done:
			return
		case evt := <-a.eventCh:
			if a.dedup.IsDuplicate(evt) {
				continue
			}

			a.procTree.Insert(evt)
			a.procTree.WALAppend(evt)
			a.correlator.Ingestion(evt)

			if a.yara != nil {
				if evt.Type == monitor.EventProcessCreate && evt.Process != nil {
					a.queueYARAScan(func() { a.scanProcessYARA(evt) })
				}
				if evt.Type == monitor.EventFileCreate && evt.File != nil && evt.File.Size <= 10*1024*1024 {
					a.queueYARAScan(func() { a.scanFileYARA(evt) })
				}
				if evt.Type == monitor.EventFileModify && evt.File != nil && evt.File.Size <= 10*1024*1024 {
					a.queueYARAScan(func() { a.scanFileYARA(evt) })
				}
			}

		case <-ancestryTick.C:
			alerts := a.procTree.DetectSuspiciousAncestry()
			for _, alertMsg := range alerts {
				log.Printf("[analysis] %s", alertMsg)
				a.eventCh <- &monitor.Event{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Type:      monitor.EventAlert,
					Severity:  monitor.SeverityWarning,
					Annotations: map[string]string{
						"correlation": "suspicious_ancestry",
						"details":     alertMsg,
					},
				}
			}

		case <-dedupStatsTick.C:
			hits, misses := a.dedup.Stats()
			total := hits + misses
			if total > 0 {
				log.Printf("[analysis] dedup: %d hits / %d total (%.1f%% saved)", hits, total, float64(hits)/float64(total)*100)
			}

		case <-scanStatsTick.C:
			hits, misses := a.scanCache.Stats()
			total := hits + misses
			if total > 0 {
				log.Printf("[analysis] scan cache: %d hits / %d total (%.1f%%)", hits, total, float64(hits)/float64(total)*100)
			}
		}
	}
}

func (a *Agent) queueYARAScan(fn func()) {
	select {
	case a.scanWorkers <- struct{}{}:
		go func() {
			defer func() { <-a.scanWorkers }()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			done := make(chan struct{}, 1)
			go func() {
				fn()
				done <- struct{}{}
			}()
			select {
			case <-done:
			case <-ctx.Done():
				log.Printf("[yara] scan timed out after 30s")
			}
		}()
	default:
		log.Printf("[yara] scan workers saturated (8/8), dropping scan")
	}
}

func (a *Agent) scanProcessYARA(evt *monitor.Event) {
	if a.yara == nil || evt.Process == nil {
		return
	}
	matches, err := a.yara.MatchProcess(evt.Process.PID)
	if err != nil {
		return
	}
	for _, m := range matches {
		log.Printf("[yara] %s matched on PID %d (%s): %s", m.Name, evt.Process.PID, evt.Process.Name, m.Description)
		alertEvt := &monitor.Event{
			ID:   uuid.New().String(), Timestamp: time.Now(),
			Type: monitor.EventAlert, Severity: m.Severity,
			Process: evt.Process,
			Annotations: map[string]string{
				"yara_rule": m.Name, "yara_desc": m.Description, "source": "yara_scan",
			},
		}
		select {
		case a.eventCh <- alertEvt:
		default:
		}
	}
}

func (a *Agent) scanFileYARA(evt *monitor.Event) {
	if a.yara == nil || evt.File == nil || evt.File.Path == "" {
		return
	}

	path := evt.File.Path

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	if cached, ok := a.scanCache.Get(path, data); ok {
		for _, m := range cached {
			alertEvt := &monitor.Event{
				ID: uuid.New().String(), Timestamp: time.Now(),
				Type: monitor.EventAlert, Severity: m.Severity,
				File: evt.File,
				Annotations: map[string]string{
					"yara_rule": m.Name, "yara_desc": m.Description, "source": "yara_scan_cached",
				},
			}
			select {
			case a.eventCh <- alertEvt:
			default:
			}
		}
		return
	}

	matches := a.yara.MatchBytes(data)

	a.scanCache.Set(path, data, matches)

	for _, m := range matches {
		log.Printf("[yara] %s matched on %s: %s", m.Name, path, m.Description)
		alertEvt := &monitor.Event{
			ID: uuid.New().String(), Timestamp: time.Now(),
			Type: monitor.EventAlert, Severity: m.Severity,
			File: evt.File,
			Annotations: map[string]string{
				"yara_rule": m.Name, "yara_desc": m.Description, "source": "yara_scan",
			},
		}
		select {
		case a.eventCh <- alertEvt:
		default:
		}
	}
}

func (a *Agent) actionPoller(ctx context.Context) {
	pollTick := time.NewTicker(a.config.PollInterval)
	defer pollTick.Stop()

	for {
		select {
		case <-a.done:
			return
		case <-pollTick.C:
			a.pollAndExecute(ctx)
		}
	}
}

func (a *Agent) pollAndExecute(ctx context.Context) {
	actions, err := a.client.PollActions(ctx, a.agentID)
	if err != nil {
		log.Printf("[trace-agent] action poll failed: %v", err)
		return
	}

	for _, action := range actions {
		go a.executeAction(ctx, action)
	}
}

func (a *Agent) executeAction(ctx context.Context, action *transport.PendingAction) {
	result, err := a.exec.Execute(ctx, action)
	if err != nil {
		log.Printf("[trace-agent] action %s failed: %v", action.ID, err)
		a.stats.ActionsFailed++
		a.client.ReportActionResult(ctx, a.agentID, action.ID, "failed", err.Error(), nil)
		return
	}

	a.stats.ActionsExecuted++
	a.client.ReportActionResult(ctx, a.agentID, action.ID, "completed", "", result)
}

func (a *Agent) getCPUUsage() float64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	var utime, stime uint64
	fmt.Sscanf(string(data), "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %d %d", &utime, &stime)
	clkTck := 100.0
	cpu := float64(utime+stime) / clkTck / time.Since(a.startedAt).Seconds() * 100
	return cpu
}

func (a *Agent) getMemoryUsage() int64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	var rss int64
	fmt.Sscanf(string(data), "VmRSS: %d kB", &rss)
	return rss / 1024
}
