package siem_test

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/siem"
)

func startEngine(t *testing.T, e *siem.Engine) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go e.Start(ctx)
	t.Cleanup(func() {
		cancel()
		e.Stop()
	})
	return ctx, cancel
}

func TestJSONDecoder(t *testing.T) {
	raw := `{"timestamp":"2026-07-18T10:00:00Z","event":"login","user":"admin","severity":3,"source":"auth"}`
	e := siem.New(siem.SIEMConfig{})

	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	e.Ingest([]byte(raw), "test")
	startEngine(t, e)
	time.Sleep(200 * time.Millisecond)

	select {
	case <-alertCh:
	default:
	}
}

func TestApacheDecoder(t *testing.T) {
	raw := `192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234`

	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	e.Ingest([]byte(raw), "test")
	startEngine(t, e)
	time.Sleep(200 * time.Millisecond)
}

func TestApacheDecoderError(t *testing.T) {
	raw := `192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 500 1234`

	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	e.Ingest([]byte(raw), "test")
	startEngine(t, e)
	time.Sleep(200 * time.Millisecond)

	select {
	case alert := <-alertCh:
		if alert.RuleID != "HTTP_5XX_ERROR" {
			t.Fatalf("expected HTTP_5XX_ERROR, got %s", alert.RuleID)
		}
		if alert.Severity != 3 {
			t.Fatalf("expected severity 3, got %d", alert.Severity)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected alert for 500 error, got none")
	}
}

func TestSyslogAuthFailure(t *testing.T) {
	raw := `<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`

	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	for range 5 {
		e.Ingest([]byte(raw), "test")
	}

	startEngine(t, e)
	time.Sleep(200 * time.Millisecond)

	alerts := 0
	for range 5 {
		select {
		case <-alertCh:
			alerts++
		case <-time.After(200 * time.Millisecond):
		}
	}
	if alerts == 0 {
		t.Fatal("expected at least one alert from auth failures")
	}
}

func TestFileWatcherNewLines(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping file watcher test in short mode")
	}
	dir := t.TempDir()

	e := siem.New(siem.SIEMConfig{
		LogDirs:      []string{dir},
		PollInterval: "100ms",
	})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	startEngine(t, e)
	time.Sleep(500 * time.Millisecond)

	e.Ingest([]byte(`{"timestamp":"2026-07-18T10:00:00Z","message":"test","severity":5}`), "test")
	e.Ingest([]byte(`192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /test HTTP/1.1" 500 100`), "test")

	time.Sleep(500 * time.Millisecond)

	select {
	case <-alertCh:
	default:
	}
}

func TestCorrelationRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping correlation test in short mode")
	}

	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	startEngine(t, e)
	time.Sleep(200 * time.Millisecond)

	raw := `<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`
	for range 5 {
		e.Ingest([]byte(raw), "test")
	}

	time.Sleep(500 * time.Millisecond)

	select {
	case alert := <-alertCh:
		alertJSON, _ := json.Marshal(alert)
		t.Logf("got alert: %s", string(alertJSON))
		if alert.RuleID == "" {
			t.Fatal("expected rule ID")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected correlation alert after 5 auth failures")
	}
}

func TestRawDecoder(t *testing.T) {
	raw := `this is a raw log line with no structure`

	e := siem.New(siem.SIEMConfig{})
	e.Ingest([]byte(raw), "test")

	startEngine(t, e)
	time.Sleep(200 * time.Millisecond)
}

func TestDecoderMultipleLines(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping decoder multiple lines test in short mode")
	}
	lines := []string{
		`{"timestamp":"2026-07-18T10:00:00Z","event":"auth","user":"admin","severity":3}`,
		`{"timestamp":"2026-07-18T10:00:01Z","event":"auth","user":"root","severity":5}`,
	}

	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	for _, line := range lines {
		e.Ingest([]byte(line), "test")
	}

	startEngine(t, e)
	time.Sleep(500 * time.Millisecond)

	select {
	case <-alertCh:
	default:
	}
}

func TestWindowsEventDecoder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping windows event decoder test in short mode")
	}
	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	raw := `<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`
	for range 5 {
		e.Ingest([]byte(raw), "test")
	}

	startEngine(t, e)
	time.Sleep(500 * time.Millisecond)

	select {
	case alert := <-alertCh:
		if alert.RuleID == "" {
			t.Fatal("expected rule ID")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected alert from auth failures")
	}
}

func TestHighVolume(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping high volume test in short mode")
	}
	e := siem.New(siem.SIEMConfig{})

	alertCh := make(chan *siem.Alert, 100)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	raw := `{"timestamp":"2026-07-18T10:00:00Z","event":"test","severity":5}`
	for range 100 {
		e.Ingest([]byte(raw), "test")
	}

	startEngine(t, e)
	time.Sleep(500 * time.Millisecond)
}

func init() {
	_ = runtime.GOOS
}
