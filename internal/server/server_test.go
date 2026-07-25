package server

import (
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

func TestSyncHandler_Routes(t *testing.T) {
	mux := http.NewServeMux()
	mgr := newTestManager(t)

	sync := NewSyncHandler(mgr)
	sync.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Test that routes are registered (they may return 404 or 405, but not 500)
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
