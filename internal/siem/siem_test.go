package siem_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/innoigniter/edge/internal/siem"
)

func TestJSONDecoder(t *testing.T) {
	raw := `{"timestamp":"2026-07-18T10:00:00Z","event":"login","user":"admin","severity":3,"source":"auth"}`
	e := siem.New(siem.SIEMConfig{})

	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	e.Ingest([]byte(raw), "test")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go e.Start(ctx)
	time.Sleep(500 * time.Millisecond)

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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go e.Start(ctx)
	time.Sleep(500 * time.Millisecond)
}

func TestApacheDecoderError(t *testing.T) {
	raw := `192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 500 1234`

	e := siem.New(siem.SIEMConfig{})

	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) {
		alertCh <- a
	})

	e.Ingest([]byte(raw), "test")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go e.Start(ctx)
	time.Sleep(500 * time.Millisecond)

	select {
	case alert := <-alertCh:
		if alert.RuleID != "HTTP_5XX_ERROR" {
			t.Fatalf("expected HTTP_5XX_ERROR, got %s", alert.RuleID)
		}
		if alert.Severity != 3 {
			t.Fatalf("expected severity 3, got %d", alert.Severity)
		}
	case <-time.After(2 * time.Second):
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go e.Start(ctx)
	time.Sleep(500 * time.Millisecond)

	alerts := 0
	for range 5 {
		select {
		case <-alertCh:
			alerts++
		case <-time.After(500 * time.Millisecond):
		}
	}

	if alerts == 0 {
		t.Fatal("expected at least one alert from auth failures")
	}
}

func TestFileWatcherNewLines(t *testing.T) {
	dir := t.TempDir()

	e := siem.New(siem.SIEMConfig{
		LogDirs:      []string{dir},
		PollInterval: "100ms",
	})

	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go e.Start(ctx)
	time.Sleep(1500 * time.Millisecond)

	e.Ingest([]byte(`{"timestamp":"2026-07-18T10:00:00Z","message":"test","severity":5}`), "test")
	e.Ingest([]byte(`192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /test HTTP/1.1" 500 100`), "test")

	time.Sleep(3 * time.Second)

	select {
	case <-alertCh:
	default:
	}
}

func TestCorrelationRule(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	e := siem.New(siem.SIEMConfig{})

	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	go e.Start(ctx)
	time.Sleep(500 * time.Millisecond)

	raw := `<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`
	for range 5 {
		e.Ingest([]byte(raw), "test")
	}

	time.Sleep(2 * time.Second)

	select {
	case alert := <-alertCh:
		alertJSON, _ := json.Marshal(alert)
		t.Logf("got alert: %s", string(alertJSON))
		if alert.RuleID == "" {
			t.Fatal("expected rule ID")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected correlation alert after 5 auth failures")
	}
}

func TestRawDecoder(t *testing.T) {
	raw := `this is a raw log line with no structure`

	e := siem.New(siem.SIEMConfig{})
	e.Ingest([]byte(raw), "test")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go e.Start(ctx)
	time.Sleep(500 * time.Millisecond)
}

func TestDecoderMultipleLines(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go e.Start(ctx)
	time.Sleep(2 * time.Second)

	select {
	case <-alertCh:
	default:
	}
}

func TestWindowsEventDecoder(t *testing.T) {
	e := siem.New(siem.SIEMConfig{})

	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	raw := `<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`
	for range 5 {
		e.Ingest([]byte(raw), "test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go e.Start(ctx)
	time.Sleep(3 * time.Second)

	select {
	case alert := <-alertCh:
		if alert.RuleID == "" {
			t.Fatal("expected rule ID")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected alert from auth failures")
	}
}

func TestHighVolume(t *testing.T) {
	e := siem.New(siem.SIEMConfig{})

	alertCh := make(chan *siem.Alert, 100)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	raw := `{"timestamp":"2026-07-18T10:00:00Z","event":"test","severity":5}`
	for range 100 {
		e.Ingest([]byte(raw), "test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go e.Start(ctx)
	time.Sleep(2 * time.Second)
}
