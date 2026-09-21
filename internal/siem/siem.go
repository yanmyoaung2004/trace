package siem

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Timestamp time.Time      `json:"timestamp"`
	Source    string         `json:"source"`
	Raw       string         `json:"raw"`
	Fields    map[string]any `json:"fields"`
	Tags      []string       `json:"tags"`
	Severity  int            `json:"severity"`
}

type Alert struct {
	ID        string       `json:"id"`
	Title     string       `json:"title"`
	Severity  int          `json:"severity"`
	MITRE     string       `json:"mitre,omitempty"`
	Source    string       `json:"source"`
	Event     *Event       `json:"event,omitempty"`
	RuleID    string       `json:"rule_id"`
	Actions   []RuleAction `json:"actions,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
}

type SIEMConfig struct {
	Enabled       bool     `json:"enabled"`
	LogDirs       []string `json:"log_dirs"`
	PollInterval  string   `json:"poll_interval"`
	SyslogUDPAddr string   `json:"syslog_udp_addr"`
	SyslogTCPAddr string   `json:"syslog_tcp_addr"`
	Workers       int      `json:"workers,omitempty"`
	MaxLineBytes  int      `json:"max_line_bytes,omitempty"`
	MaxConns      int      `json:"max_conns,omitempty"`
}

// Tunables with boring defaults; New fills zero values.
const (
	defaultWorkers      = 4
	defaultMaxLineBytes = 256 * 1024
	defaultMaxConns     = 100
)

type Engine struct {
	cfg        SIEMConfig
	decoders   []Decoder
	ruleEngine *RuleEngine
	eventCh    chan *Event
	alertCh    chan *Alert
	alertFn    func(*Alert)
	closeCh    chan struct{}
	closeOnce  sync.Once
	workers    int
	maxLine    int
	connSem    chan struct{}
	connWg     sync.WaitGroup

	filePositions map[string]int64
	posMu         sync.Mutex

	alertDedup *alertDedup
	truncated  int64 // lines dropped by the line cap
}

// Truncated returns the count of lines dropped by the line cap.
func (e *Engine) Truncated() int64 { return atomic.LoadInt64(&e.truncated) }

func New(cfg SIEMConfig) *Engine {
	registerDefaultDecoders()
	workers := cfg.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}
	maxLine := cfg.MaxLineBytes
	if maxLine <= 0 {
		maxLine = defaultMaxLineBytes
	}
	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	e := &Engine{
		cfg:           cfg,
		decoders:      buildDecoders(),
		ruleEngine:    NewRuleEngine(),
		eventCh:       make(chan *Event, 10000),
		alertCh:       make(chan *Alert, 1000),
		closeCh:       make(chan struct{}),
		workers:       workers,
		maxLine:       maxLine,
		connSem:       make(chan struct{}, maxConns),
		filePositions: make(map[string]int64),
		alertDedup:    newAlertDedup(),
	}

	e.ruleEngine.LoadDefault()
	e.ruleEngine.LoadBuiltinYAML()

	return e
}

func (e *Engine) OnAlert(fn func(*Alert)) {
	e.alertFn = fn
}

func (e *Engine) Start(ctx context.Context) error {
	e.ruleEngine.LoadDefault()

	log.Printf("siem engine started (poll: %v, udp: %s, tcp: %s)",
		e.cfg.PollInterval, e.cfg.SyslogUDPAddr, e.cfg.SyslogTCPAddr)

	for range e.workers {
		go e.processEvents(ctx)
	}

	for _, dir := range e.cfg.LogDirs {
		go e.watchDirectory(ctx, dir)
	}

	if e.cfg.SyslogUDPAddr != "" {
		go e.listenSyslogUDP(ctx)
	}

	if e.cfg.SyslogTCPAddr != "" {
		go e.listenSyslogTCP(ctx)
	}

	go e.dispatchAlerts(ctx)

	return nil
}

func (e *Engine) Stop() {
	e.closeOnce.Do(func() { close(e.closeCh) })
}

func (e *Engine) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-e.eventCh:
			alerts := e.ruleEngine.Evaluate(event)
			for _, alert := range alerts {
				select {
				case e.alertCh <- alert:
				default:
					log.Printf("siem: alert channel full, dropping alert: %s", alert.Title)
				}
			}
		}
	}
}

func (e *Engine) dispatchAlerts(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case alert := <-e.alertCh:
			alertJSON, _ := json.Marshal(alert)
			log.Printf("SIEM ALERT: [%d] %s — %s", alert.Severity, alert.Title, string(alertJSON))

			// Dedup: suppress repeated alerts within 5 minutes
			dedupKey := fmt.Sprintf("%s|%s", alert.Title, alert.RuleID)
			if !e.alertDedup.shouldSend(dedupKey) {
				continue
			}

			if e.alertFn != nil {
				e.alertFn(alert)
			}
		}
	}
}

func (e *Engine) Ingest(raw []byte, source string) {
	e.ingest(raw, source)
}

func (e *Engine) ingest(raw []byte, source string) {
	event := fastDecode(raw)
	if event == nil {
		for _, dec := range e.decoders {
			if dec.Name() == "auto" || dec.Name() == "json" {
				continue
			}
			if evt, err := dec.Decode(raw); err == nil {
				event = evt
				break
			}
		}
	}

	if event == nil {
		event = &Event{
			Timestamp: time.Now().UTC(),
			Source:    source,
			Raw:       string(raw),
			Fields:    map[string]any{"message": string(raw)},
		}
	} else {
		event.Source = source + "->" + event.Source
	}

	select {
	case e.eventCh <- event:
	default:
		log.Printf("siem: event channel full, dropping event from %s", source)
	}
}

// fastDecode handles the hot path: JSON lines decode without walking the
// whole decoder chain. Non-JSON falls through to the registry order.
func fastDecode(raw []byte) *Event {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil
	}
	var fields map[string]any
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return nil
	}
	e := &Event{
		Timestamp: time.Now().UTC(),
		Source:    "decoder:json",
		Raw:       string(raw),
		Fields:    fields,
	}
	if ts, ok := fields["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			e.Timestamp = t.UTC()
		}
	}
	if sev, ok := fields["severity"].(float64); ok {
		e.Severity = int(sev)
	}
	return e
}

func (e *Engine) watchDirectory(ctx context.Context, dir string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			log.Printf("siem: read dir %s: %v", dir, err)
			time.Sleep(10 * time.Second)
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			e.checkFile(ctx, path)
		}

		time.Sleep(5 * time.Second)
	}
}

func (e *Engine) checkFile(ctx context.Context, path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	e.posMu.Lock()
	lastPos, exists := e.filePositions[path]
	if !exists {
		e.filePositions[path] = info.Size()
		e.posMu.Unlock()
		e.ingestFile(ctx, path, 0)
		return
	}
	e.posMu.Unlock()

	if info.Size() <= lastPos {
		return
	}

	e.ingestFile(ctx, path, lastPos)
}

func (e *Engine) ingestFile(ctx context.Context, path string, offset int64) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("siem: open %s: %v", path, err)
		return
	}
	defer f.Close()

	if _, err := f.Seek(offset, 0); err != nil {
		log.Printf("siem: seek %s: %v", path, err)
		return
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*64), e.maxLine)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)
		e.ingest(lineCopy, "file:"+filepath.Base(path))
	}
	if err := scanner.Err(); err != nil {
		// Line longer than the cap: count it and skip, don't stall the file.
		atomic.AddInt64(&e.truncated, 1)
		log.Printf("siem: line too long in %s (cap %d), counted and skipped", path, e.maxLine)
	}

	stat, err := os.Stat(path)
	if err == nil {
		e.posMu.Lock()
		e.filePositions[path] = stat.Size()
		// Bound memory: filePositions never evicted before, leak on rotation.
		if len(e.filePositions) > 1024 {
			for k := range e.filePositions {
				delete(e.filePositions, k)
				break
			}
		}
		e.posMu.Unlock()
	}
}

func (e *Engine) listenSyslogUDP(ctx context.Context) {
	addr, err := net.ResolveUDPAddr("udp", e.cfg.SyslogUDPAddr)
	if err != nil {
		log.Printf("siem: resolve udp addr: %v", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("siem: listen udp %s: %v", e.cfg.SyslogUDPAddr, err)
		return
	}
	defer conn.Close()

	log.Printf("siem: listening UDP syslog on %s", e.cfg.SyslogUDPAddr)

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("siem: udp read error: %v", err)
			continue
		}

		line := make([]byte, n)
		copy(line, buf[:n])
		e.ingest(line, "syslog:udp")
	}
}

func (e *Engine) listenSyslogTCP(ctx context.Context) {
	addr, err := net.ResolveTCPAddr("tcp", e.cfg.SyslogTCPAddr)
	if err != nil {
		log.Printf("siem: resolve tcp addr: %v", err)
		return
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Printf("siem: listen tcp %s: %v", e.cfg.SyslogTCPAddr, err)
		return
	}
	defer listener.Close()

	log.Printf("siem: listening TCP syslog on %s", e.cfg.SyslogTCPAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			log.Printf("siem: tcp accept error: %v", err)
			continue
		}

		select {
		case e.connSem <- struct{}{}:
		default:
			conn.Close()
			log.Printf("siem: tcp conn limit reached, refused connection")
			continue
		}
		e.connWg.Add(1)
		go func(c net.Conn) {
			defer e.connWg.Done()
			defer func() { <-e.connSem }()
			e.handleTCPConn(ctx, c)
		}(conn)
	}
}

func (e *Engine) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*64), e.maxLine)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)
		e.ingest(lineCopy, "syslog:tcp")
	}
	if err := scanner.Err(); err != nil {
		atomic.AddInt64(&e.truncated, 1)
	}
}
