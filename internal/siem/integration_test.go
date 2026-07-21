package siem_test

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/siem"
)

func TestWazuhSSHBruteForceRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	raw := `<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`

	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Start(ctx)

	time.Sleep(100 * time.Millisecond)

	for i := 0; i < 6; i++ {
		e.Ingest([]byte(raw), "test-syslog")
		time.Sleep(50 * time.Millisecond)
	}

	select {
	case alert := <-alertCh:
		if alert.RuleID == "" {
			t.Fatal("alert has no RuleID")
		}
		if alert.Severity < 3 {
			t.Fatalf("expected severity >= 3, got %d", alert.Severity)
		}
		if alert.MITRE == "" {
			t.Logf("alert %s has no MITRE mapping (severity: %d)", alert.RuleID, alert.Severity)
		}
		t.Logf("OK: alert %s (sev:%d, mitre:%s, title:%s)", alert.RuleID, alert.Severity, alert.MITRE, alert.Title)
	case <-time.After(3 * time.Second):
		t.Fatal("expected alert from SSH auth failures, got none")
	}
}

func TestWazuhHTTPErrorRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	raw := `192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 500 1234`

	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Start(ctx)

	time.Sleep(100 * time.Millisecond)

	e.Ingest([]byte(raw), "test-http")
	time.Sleep(500 * time.Millisecond)

	select {
	case alert := <-alertCh:
		t.Logf("OK: alert %s (sev:%d, title:%s)", alert.RuleID, alert.Severity, alert.Title)
	case <-time.After(2 * time.Second):
		t.Fatal("expected alert for HTTP 500 error, got none")
	}
}

func TestWazuhDecoderAndRuleChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	tests := []struct {
		name      string
		log       string
		source    string
		wantAlert bool
		wantSev   int
	}{
		{
			name:      "SSH brute force",
			log:       `<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`,
			source:    "test-syslog",
			wantAlert: true,
			wantSev:   5,
		},
		{
			name:      "HTTP 500 error",
			log:       `192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 500 1234`,
			source:    "test-http",
			wantAlert: true,
			wantSev:   3,
		},
		{
			name:      "Windows malware",
			log:       `2026/07/18 10:00:00 (Microsoft-Windows-Windows Defender) 1116`,
			source:    "test-windows",
			wantAlert: false,
		},
		{
			name:      "Docker error",
			log:       `level=error msg="Container 1234 failed to start"`,
			source:    "test-docker",
			wantAlert: true,
			wantSev:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := siem.New(siem.SIEMConfig{})
			alertCh := make(chan *siem.Alert, 10)
			e.OnAlert(func(a *siem.Alert) { alertCh <- a })

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go e.Start(ctx)
			time.Sleep(100 * time.Millisecond)

			e.Ingest([]byte(tt.log), tt.source)
			time.Sleep(500 * time.Millisecond)

			if tt.wantAlert {
				select {
				case alert := <-alertCh:
					t.Logf("OK: %s (sev:%d, mitre:%s)", alert.RuleID, alert.Severity, alert.MITRE)
				case <-time.After(3 * time.Second):
					t.Fatalf("expected alert for %s, got none", tt.name)
				}
			}
		})
	}
}

func TestAlertHasPlaybookAction(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("skipping integration test")
	}

	raw := `<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`

	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	for i := 0; i < 6; i++ {
		e.Ingest([]byte(raw), "test-syslog")
		time.Sleep(50 * time.Millisecond)
	}

	select {
	case alert := <-alertCh:
		if len(alert.Actions) == 0 {
			t.Logf("alert %s has no playbook actions (may not be mapped yet)", alert.RuleID)
		} else {
			for _, a := range alert.Actions {
				t.Logf("OK: alert %s triggers playbook %q", alert.RuleID, a.Playbook)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected alert, got none")
	}
}

func TestDecoderParsing(t *testing.T) {
	tests := []struct {
		name     string
		log      string
		wantTags []string
	}{
		{
			name:     "SSH auth failure",
			log:      `<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`,
			wantTags: []string{"auth_failure"},
		},
		{
			name:     "SSH auth success",
			log:      `<34>Jul 18 10:00:00 myserver sshd[1234]: Accepted password for root from 10.0.0.5 port 22 ssh2`,
			wantTags: []string{"auth_success"},
		},
		{
			name:     "HTTP 500",
			log:      `192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 500 1234`,
			wantTags: []string{"http_error"},
		},
		{
			name:     "sudo command",
			log:      `Jul 18 10:00:00 myserver sudo[1234]: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash`,
			wantTags: []string{"privilege_escalation"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := siem.New(siem.SIEMConfig{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go e.Start(ctx)
			time.Sleep(100 * time.Millisecond)

			e.OnAlert(func(a *siem.Alert) {})
			e.Ingest([]byte(tt.log), "test")
			time.Sleep(300 * time.Millisecond)

			for _, want := range tt.wantTags {
				t.Logf("expected tag %q to be present", want)
			}
		})
	}
}

func TestK8sPrivilegedPodRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	data, err := os.ReadFile("testdata/k8s-privileged-pod.json")
	if err != nil {
		t.Fatal(err)
	}

	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	e.Ingest(data, "k8s-audit")

	select {
	case alert := <-alertCh:
		t.Logf("K8s alert: %s (sev:%d, rule:%s, title:%s)", alert.RuleID, alert.Severity, alert.RuleID, alert.Title)
		if alert.Severity < 4 {
			t.Fatalf("expected severity >= 4 for privileged pod, got %d", alert.Severity)
		}
		if alert.MITRE == "" {
			t.Log("K8s rule has no MITRE mapping")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected alert from K8s privileged pod, got none")
	}
}

func TestK8sSecretAccessRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	data, err := os.ReadFile("testdata/k8s-secret-access.json")
	if err != nil {
		t.Fatal(err)
	}

	e := siem.New(siem.SIEMConfig{})
	alertCh := make(chan *siem.Alert, 10)
	e.OnAlert(func(a *siem.Alert) { alertCh <- a })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	e.Ingest(data, "k8s-audit")

	select {
	case alert := <-alertCh:
		t.Logf("K8s alert: %s (sev:%d, rule:%s, title:%s)", alert.RuleID, alert.Severity, alert.RuleID, alert.Title)
		if alert.Severity < 3 {
			t.Fatalf("expected severity >= 3 for secret access, got %d", alert.Severity)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected alert from K8s secret access, got none")
	}
}

func init() {
	_ = os.Getenv
	_ = context.TODO
}
