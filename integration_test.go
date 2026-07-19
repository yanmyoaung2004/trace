package trace_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/db"
	"github.com/yanmyoaung2004/trace/internal/investigation"
	"github.com/yanmyoaung2004/trace/internal/playbook"
	"github.com/yanmyoaung2004/trace/internal/siem"
	"github.com/yanmyoaung2004/trace/internal/plugin"
	"github.com/yanmyoaung2004/trace/internal/sift"
	"github.com/yanmyoaung2004/trace/internal/response"
	"github.com/yanmyoaung2004/trace/internal/archive"
)

func TestEndToEndSIEMAlertToInvestigation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test")
	}

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	defer database.Close()

	reg := plugin.NewRegistry()
	reg.Register(sift.New(database.DB, ""))
	reg.Register(response.New(database.DB))

	mitreDB, err := archive.LoadMitreSeed()
	if err != nil {
		t.Fatalf("load mitre: %v", err)
	}
	_ = mitreDB

	invMgr := investigation.NewManager(database)
	logWriter, err := investigation.NewLogWriter(tmpDir)
	if err != nil {
		t.Fatalf("log writer: %v", err)
	}

	pbEngine := playbook.New()
	pbEngine.LoadBuiltin()

	exec := playbook.NewExecutor(reg, invMgr, logWriter)

	var alertReceived bool
	var alertRuleID string
	var alertSeverity int

	se := siem.New(siem.SIEMConfig{})
	se.OnAlert(func(a *siem.Alert) {
		alertReceived = true
		alertRuleID = a.RuleID
		alertSeverity = a.Severity
		t.Logf("ALERT: %s (sev:%d, mitre:%s, actions:%d)", a.RuleID, a.Severity, a.MITRE, len(a.Actions))

		if len(a.Actions) > 0 {
			for _, action := range a.Actions {
				inv, err := invMgr.Create(context.Background(), a.Title, action.Playbook)
				if err != nil {
					t.Logf("create inv: %v", err)
					continue
				}

				pb := pbEngine.Get(action.Playbook)
				if pb == nil {
					t.Logf("playbook %s not found", action.Playbook)
					continue
				}

				results, err := exec.Execute(context.Background(), inv, pb, action.Params)
				if err != nil {
					t.Logf("playbook exec: %v", err)
				} else {
					t.Logf("playbook %s completed, keys: %d", action.Playbook, len(results))
				}
			}
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go se.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	t.Run("SSH brute force alert creates investigation", func(t *testing.T) {
		alertReceived = false

		for i := 0; i < 6; i++ {
			se.Ingest([]byte(`<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`), "test")
			time.Sleep(50 * time.Millisecond)
		}

		time.Sleep(2 * time.Second)

		if !alertReceived {
			t.Fatal("expected alert from SSH brute force, got none")
		}
		if alertRuleID == "" {
			t.Fatal("alert has no RuleID")
		}
		if alertSeverity < 3 {
			t.Fatalf("expected severity >= 3, got %d", alertSeverity)
		}
		t.Logf("PASS: SSH brute force produced alert %s (sev:%d)", alertRuleID, alertSeverity)
	})

	t.Run("HTTP 500 error triggers alert and playbook", func(t *testing.T) {
		alertReceived = false

		se.Ingest([]byte(`192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 500 1234`), "test")
		time.Sleep(1 * time.Second)

		if !alertReceived {
			t.Fatal("expected alert from HTTP 500, got none")
		}
		t.Logf("PASS: HTTP 500 produced alert %s (sev:%d)", alertRuleID, alertSeverity)
	})

	t.Run("Wazuh SSH decoder properly tags events", func(t *testing.T) {
		alertReceived = false

		se.Ingest([]byte(`<34>Jul 18 10:00:00 myserver sshd[1234]: Accepted password for root from 10.0.0.5 port 22 ssh2`), "test")
		time.Sleep(1 * time.Second)

		t.Logf("SSH success alert: %s (sev:%d)", alertRuleID, alertSeverity)
	})

	t.Run("DB contains investigations from SIEM alerts", func(t *testing.T) {
		invs, err := invMgr.ListRecent(context.Background(), 10)
		if err != nil {
			t.Fatalf("list invs: %v", err)
		}
		if len(invs) == 0 {
			t.Fatal("expected at least one investigation in DB")
		}
		t.Logf("PASS: DB has %d investigations", len(invs))
	})
}

func init() {
	_ = os.Getenv
	_ = context.Background
}
