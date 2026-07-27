package monitor

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LogCollector tails log files and emits events for new lines.
// Supports syslog, auditd, and custom log paths.
type LogCollector struct {
	paths   []string
	eventCh chan<- *Event
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewLogCollector creates a log collector that tails the given paths.
func NewLogCollector(eventCh chan<- *Event, paths []string) *LogCollector {
	return &LogCollector{
		paths:   paths,
		eventCh: eventCh,
		done:    make(chan struct{}),
	}
}

func (l *LogCollector) Start(ctx context.Context) error {
	log.Printf("[log-collector] watching %d paths", len(l.paths))
	for _, p := range l.paths {
		l.wg.Add(1)
		go l.tail(ctx, p)
	}
	return nil
}

func (l *LogCollector) Stop() {
	close(l.done)
	l.wg.Wait()
}

func (l *LogCollector) tail(ctx context.Context, path string) {
	defer l.wg.Done()

	// Wait for file to exist
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-l.done:
			return
		case <-time.After(5 * time.Second):
		}
	}

	// Open file and seek to end (don't re-read existing content)
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[log-collector] open %s: %v", path, err)
		return
	}
	defer f.Close()

	// Seek to end
	if _, err := f.Seek(0, 2); err != nil {
		log.Printf("[log-collector] seek %s: %v", path, err)
		return
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.done:
			return
		default:
			if !scanner.Scan() {
				// Check for errors
				if err := scanner.Err(); err != nil {
					log.Printf("[log-collector] read %s: %v", path, err)
				}
				// File not grown yet — wait and retry
				time.Sleep(500 * time.Millisecond)
				continue
			}

			line := scanner.Text()
			if line == "" {
				continue
			}

			// Determine log source from path
			source := detectLogSource(path, line)

			// Determine severity
			severity := detectSeverity(line)

			evt := &Event{
				ID:        fmt.Sprintf("log-%d-%d", time.Now().UnixNano(), fastRand()),
				Type:      EventType(source),
				Severity:  Severity(severity),
				Timestamp: time.Now(),
				Raw: map[string]any{
					"log": line,
				},
				Annotations: map[string]string{
					"source": "log_collector",
					"path":   path,
				},
			}

			select {
			case l.eventCh <- evt:
			default:
				// Drop if channel full
			}
		}
	}
}

func detectLogSource(path, line string) string {
	name := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(name, "auth.log"), strings.Contains(name, "secure"):
		return "log_auth"
	case strings.Contains(name, "syslog"), strings.Contains(name, "messages"):
		return "log_syslog"
	case strings.Contains(name, "audit"):
		return "log_audit"
	case strings.Contains(name, "apache"), strings.Contains(name, "access.log"):
		return "log_http"
	case strings.Contains(name, "nginx"):
		return "log_http"
	case strings.Contains(name, "dmesg"), strings.Contains(name, "kern.log"):
		return "log_kernel"
	default:
		return "log_generic"
	}
}

func detectSeverity(line string) int {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "critical") || strings.Contains(lower, "emergency"):
		return 10
	case strings.Contains(lower, "error") || strings.Contains(lower, "err"):
		return 7
	case strings.Contains(lower, "warn") || strings.Contains(lower, "warning"):
		return 5
	case strings.Contains(lower, "notice"):
		return 3
	case strings.Contains(lower, "info"):
		return 1
	default:
		return 3
	}
}

func fastRand() int64 {
	return int64(time.Now().UnixNano() & 0xFFFF)
}
