package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/db"
)

func newTestManager(t *testing.T) *ServerManager {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return NewServerManager(database)
}

func TestHealthzEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestReadyzEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, _ := server.Client().Get(server.URL + "/readyz")
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNewServerManager(t *testing.T) {
	m := newTestManager(t)
	if m == nil {
		t.Fatal("expected manager")
	}
}

func TestServerManager_Migrate(t *testing.T) {
	m := newTestManager(t)
	if err := m.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	tables := []string{"server_nodes", "server_investigations", "server_users",
		"server_correlations", "edr_agents", "edr_events",
		"edr_actions", "edr_fp_counters", "compliance_snapshots", "server_orgs"}
	for _, tbl := range tables {
		var name string
		err := m.db.QueryRow(fmt.Sprintf("SELECT name FROM sqlite_master WHERE type='table' AND name='%s'", tbl)).Scan(&name)
		if err != nil || name == "" {
			t.Errorf("table %s not found after migration", tbl)
		}
	}
}

func TestSyncHandler_Routes(t *testing.T) {
	mux := http.NewServeMux()
	mgr := newTestManager(t)

	sync := NewSyncHandler(mgr)
	sync.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	routes := []string{"/", "/api/investigations", "/api/orgs", "/api/users"}
	for _, route := range routes {
		resp, err := server.Client().Get(server.URL + route)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Errorf("%s returned %d (server error)", route, resp.StatusCode)
		}
	}
}

func TestSyncHandler_Auth(t *testing.T) {
	mgr := newTestManager(t)
	mgr.Migrate()
	apiKey, err := mgr.SeedDefaultUser(context.Background())
	if err != nil {
		t.Fatalf("SeedDefaultUser: %v", err)
	}
	if apiKey == "" {
		t.Fatal("expected non-empty api key")
	}

	mux := http.NewServeMux()
	sync := NewSyncHandler(mgr)
	sync.RegisterRoutes(mux)

	t.Run("no auth returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/nodes", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("status = %d, want 401", rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err == nil {
			if body["error"] == "" {
				t.Error("expected error message in response body")
			}
		}
	})

	t.Run("valid bearer token returns 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/nodes", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("valid api_key query param returns 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/nodes?api_key="+apiKey, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}

func TestSyncHandler_Health(t *testing.T) {
	mux := http.NewServeMux()
	mgr := newTestManager(t)
	sync := NewSyncHandler(mgr)
	sync.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf(`status = %q, want "ok"`, body["status"])
	}
}

func TestSyncHandler_NodesEndpoint(t *testing.T) {
	mgr := newTestManager(t)
	mgr.Migrate()
	apiKey, err := mgr.SeedDefaultUser(context.Background())
	if err != nil {
		t.Fatalf("SeedDefaultUser: %v", err)
	}

	mux := http.NewServeMux()
	sync := NewSyncHandler(mgr)
	sync.RegisterRoutes(mux)

	t.Run("returns empty node list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/nodes?api_key="+apiKey, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		var nodes []NodeInfo
		if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}
		if nodes == nil {
			t.Error("expected non-nil node list")
		}
	})

	t.Run("returns registered node", func(t *testing.T) {
		node, err := mgr.RegisterNode(context.Background(), "test-node", "1.0.0")
		if err != nil {
			t.Fatalf("RegisterNode: %v", err)
		}
		req := httptest.NewRequest("GET", "/api/v1/nodes?api_key="+apiKey, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		var nodes []NodeInfo
		if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}
		if len(nodes) != 1 {
			t.Fatalf("expected 1 node, got %d", len(nodes))
		}
		if nodes[0].ID != node.ID {
			t.Errorf("node ID = %q, want %q", nodes[0].ID, node.ID)
		}
		if nodes[0].Hostname != "test-node" {
			t.Errorf("hostname = %q, want %q", nodes[0].Hostname, "test-node")
		}
	})
}

func TestDashboardHandler_Routes(t *testing.T) {
	mux := http.NewServeMux()
	mgr := newTestManager(t)

	dash := NewDashboardHandler(mgr)
	dash.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestDashboardHandler_WithData(t *testing.T) {
	mgr := newTestManager(t)
	mgr.db.Exec(`CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, status TEXT, intent TEXT, created_at TEXT)`)
	mgr.db.Exec(`INSERT INTO investigations VALUES ('inv-1', 'open', 'test inv', '2026-01-01')`)
	mux := http.NewServeMux()
	dash := NewDashboardHandler(mgr)
	dash.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, _ := server.Client().Get(server.URL + "/")
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestDashboardHandler_Detail(t *testing.T) {
	mgr := newTestManager(t)
	mgr.Migrate()

	longID := "inv-det-1-abcdef123456"
	_, err := mgr.db.Exec(`INSERT INTO server_investigations (id, node_id, status, intent, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		longID, "node-1", "completed", "detail test", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	mux := http.NewServeMux()
	dash := NewDashboardHandler(mgr)
	dash.RegisterRoutes(mux)

	t.Run("valid id returns 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/investigations/"+longID, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "detail test") {
			t.Error("response should contain investigation intent")
		}
	})

	t.Run("invalid id returns 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/investigations/nonexistent", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("empty id returns 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/investigations/", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})
}

func TestDashboardHandler_Cases(t *testing.T) {
	mgr := newTestManager(t)
	dbSQL := mgr.db.DB
	mux := http.NewServeMux()
	dash := NewDashboardHandler(mgr)
	dash.WithDB(dbSQL)
	dash.RegisterRoutes(mux)

	t.Run("GET returns 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/cases", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("POST creates case and redirects", func(t *testing.T) {
		body := strings.NewReader("title=Test+Case&severity=high&description=Created+during+test")
		req := httptest.NewRequest("POST", "/cases", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 303 {
			t.Errorf("status = %d, want 303", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/cases" {
			t.Errorf("Location = %q, want /cases", loc)
		}
	})

	t.Run("POST with empty title defaults to Untitled Case", func(t *testing.T) {
		body := strings.NewReader("severity=low")
		req := httptest.NewRequest("POST", "/cases", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 303 {
			t.Errorf("status = %d, want 303", rec.Code)
		}
	})

	t.Run("POST without DB returns 404", func(t *testing.T) {
		muxNoDB := http.NewServeMux()
		dashNoDB := NewDashboardHandler(mgr)
		dashNoDB.RegisterRoutes(muxNoDB)

		body := strings.NewReader("title=No+DB+Case")
		req := httptest.NewRequest("POST", "/cases", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		muxNoDB.ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})
}

func TestDashboardHandler_Alerts(t *testing.T) {
	mgr := newTestManager(t)
	dbSQL := mgr.db.DB
	mux := http.NewServeMux()
	dash := NewDashboardHandler(mgr)
	dash.WithDB(dbSQL)
	dash.RegisterRoutes(mux)

	_, err := mgr.db.Exec(`INSERT INTO alerts (id, title, severity, source, created_at) VALUES (?, ?, ?, ?, datetime('now'))`,
		"alert-test-1", "Test Critical Alert", 8, "wazuh")
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	_, err = mgr.db.Exec(`INSERT INTO alerts (id, title, severity, source, created_at) VALUES (?, ?, ?, ?, datetime('now'))`,
		"alert-test-2", "Test Low Alert", 2, "wazuh")
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}

	t.Run("no filter returns 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/alerts", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Test Critical Alert") {
			t.Error("response should contain critical alert title")
		}
		if !strings.Contains(body, "Test Low Alert") {
			t.Error("response should contain low alert title")
		}
	})

	t.Run("severity filter returns filtered results", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/alerts?severity=7", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Test Critical Alert") {
			t.Error("response should contain critical alert with severity 8")
		}
	})

	t.Run("no alerts returns empty state", func(t *testing.T) {
		muxEmpty := http.NewServeMux()
		mgrEmpty := newTestManager(t)
		dashEmpty := NewDashboardHandler(mgrEmpty)
		dashEmpty.WithDB(mgrEmpty.db.DB)
		dashEmpty.RegisterRoutes(muxEmpty)

		req := httptest.NewRequest("GET", "/alerts", nil)
		rec := httptest.NewRecorder()
		muxEmpty.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "No alerts") {
			t.Error("expected empty state message when no alerts exist")
		}
	})

	t.Run("without DB returns 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/alerts", nil)
		rec := httptest.NewRecorder()

		muxNoDB := http.NewServeMux()
		dashNoDB := NewDashboardHandler(mgr)
		dashNoDB.RegisterRoutes(muxNoDB)
		muxNoDB.ServeHTTP(rec, req)

		if rec.Code != 404 {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})
}

func TestDashboardHandler_LiveData(t *testing.T) {
	mgr := newTestManager(t)
	mgr.Migrate()

	_, err := mgr.db.Exec(`INSERT INTO server_investigations (id, node_id, status, intent, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"inv-live-1-abcdefghijk", "node-1", "running", "live test", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	mux := http.NewServeMux()
	dash := NewDashboardHandler(mgr)
	dash.RegisterRoutes(mux)

	t.Run("returns 200 with valid JSON", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/live", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}
		if body["investigations"] == nil {
			t.Error("expected investigations in response")
		}
		if body["time"] == nil {
			t.Error("expected time in response")
		}

		invs, ok := body["investigations"].([]any)
		if !ok {
			t.Fatal("investigations should be an array")
		}
		if len(invs) != 1 {
			t.Fatalf("expected 1 investigation, got %d", len(invs))
		}
	})

	t.Run("empty data returns empty array", func(t *testing.T) {
		mgrEmpty := newTestManager(t)
		mgrEmpty.Migrate()

		muxEmpty := http.NewServeMux()
		dashEmpty := NewDashboardHandler(mgrEmpty)
		dashEmpty.RegisterRoutes(muxEmpty)

		req := httptest.NewRequest("GET", "/api/live", nil)
		rec := httptest.NewRecorder()
		muxEmpty.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}
		if _, ok := body["investigations"]; !ok {
			t.Error("expected investigations field in response")
		}
	})
}

func TestDashboardHandler_TSEStatus(t *testing.T) {
	mux := http.NewServeMux()
	mgr := newTestManager(t)
	dash := NewDashboardHandler(mgr)
	dash.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/tse", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}

	expectedKeys := []string{"events_enqueued", "events_written", "events_flushed",
		"events_dropped", "queue_depth", "watermark_age_sec",
		"parquet_files_created", "parquet_bytes_written",
		"hot_table_count", "cold_file_count", "flush_errors"}
	for _, key := range expectedKeys {
		if _, ok := body[key]; !ok {
			t.Errorf("missing key in response: %s", key)
		}
	}
}

func TestDashboardHandler_Correlations(t *testing.T) {
	mgr := newTestManager(t)
	mgr.Migrate()

	mux := http.NewServeMux()
	dash := NewDashboardHandler(mgr)
	dash.RegisterRoutes(mux)

	t.Run("empty correlations returns 200", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/correlations", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "No correlations yet") {
			t.Error("expected empty state message")
		}
	})

	t.Run("with data returns 200", func(t *testing.T) {
		_, err := mgr.db.Exec(
			`INSERT INTO server_correlations (id, ioc, node_ids, count, confidence, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"corr-1", "8.8.8.8", `["node-1","node-2"]`, 2, 0.75, "2026-01-01", "2026-01-02")
		if err != nil {
			t.Fatalf("insert correlation: %v", err)
		}

		req := httptest.NewRequest("GET", "/correlations", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "8.8.8.8") {
			t.Error("response should contain IOC value")
		}
	})
}

func TestSyncHandler_InvestigationList(t *testing.T) {
	mgr := newTestManager(t)
	mgr.db.Exec(`CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, status TEXT, intent TEXT, created_at TEXT, updated_at TEXT)`)
	mgr.db.Exec(`INSERT OR IGNORE INTO investigations VALUES ('inv-1', 'open', 'test investigation', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)

	mux := http.NewServeMux()
	sync := NewSyncHandler(mgr)
	sync.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/api/investigations")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 500 {
		t.Fatal("investigations endpoint returned 500")
	}
}

func TestOrgManagement(t *testing.T) {
	mgr := newTestManager(t)
	mgr.db.Exec(`CREATE TABLE IF NOT EXISTS orgs (id TEXT PRIMARY KEY, name TEXT UNIQUE, created_at TEXT)`)

	mux := http.NewServeMux()
	sync := NewSyncHandler(mgr)
	sync.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	body := strings.NewReader(`{"name":"test-org"}`)
	resp, err := server.Client().Post(server.URL+"/api/orgs", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		t.Errorf("POST /api/orgs returned %d", resp.StatusCode)
	}
}

func TestServeHTTP(t *testing.T) {
	mgr := newTestManager(t)
	mgr.Migrate()

	opts := ServeOptions{
		ListenAddr: "127.0.0.1:0",
		LogDir:     t.TempDir(),
		DB:         mgr.db.DB,
	}

	srv, err := ServeHTTP(opts, mgr, mgr)
	if err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	srv.Close()

	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	if srv.Handler == nil {
		t.Fatal("expected non-nil handler")
	}
}
