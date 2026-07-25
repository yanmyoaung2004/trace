package exporter

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"
)

func TestAgentName(t *testing.T) {
	a := New(nil)
	if a.Name() != "exporter" {
		t.Errorf("name = %q", a.Name())
	}
}

func TestCapabilities(t *testing.T) {
	a := New(nil)
	caps := a.Capabilities()
	if len(caps) == 0 {
		t.Fatal("expected capabilities")
	}
	if caps[0].Action != "serve_reports" {
		t.Errorf("action = %q", caps[0].Action)
	}
}

func TestExecute_UnknownAction(t *testing.T) {
	a := New(nil)
	_, err := a.Execute(context.Background(), map[string]any{"action": "unknown"})
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestExecute_ServeReports(t *testing.T) {
	// Create an in-memory SQLite database
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	a := New(db)
	out, err := a.Execute(context.Background(), map[string]any{
		"action": "serve_reports",
		"addr":   ":0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["status"] != "started" {
		t.Errorf("status = %v", out["status"])
	}

	if a.srv != nil {
		a.srv.Close()
	}
}

func TestListHandler(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Create the investigations table
	db.Exec(`CREATE TABLE investigations (id TEXT PRIMARY KEY, status TEXT, intent TEXT, created_at TEXT)`)

	a := New(db)
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.listHandler)

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

func TestListHandler_WithData(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	db.Exec(`CREATE TABLE investigations (id TEXT PRIMARY KEY, status TEXT, intent TEXT, created_at TEXT)`)
	db.Exec(`INSERT INTO investigations VALUES ('00000000-0000-0000-0000-000000000001', 'open', 'test investigation', '2026-01-01')`)

	a := New(db)
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.listHandler)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, _ := server.Client().Get(server.URL + "/")
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
