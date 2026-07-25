package hunt

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/db"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return NewManager(d)
}

func TestHuntCreate(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	params := map[string]any{"source": "siem"}
	h, err := m.Create(ctx, "Test Hunt", "A test hunt", "*/5 * * * *", "test-playbook", params, "self", 3)
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "Test Hunt" {
		t.Errorf("name = %q", h.Name)
	}
	if h.Status != "active" {
		t.Errorf("status = %q", h.Status)
	}
	if h.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestHuntGet(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	h, _ := m.Create(ctx, "Get Test", "", "* * * * *", "pb", nil, "self", 1)
	got, err := m.Get(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Get Test" {
		t.Errorf("name = %q", got.Name)
	}
}

func TestHuntGet_NotFound(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHuntGetByName(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	m.Create(ctx, "ByName", "", "* * * * *", "pb", nil, "self", 0)
	got, err := m.GetByName(ctx, "ByName")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "ByName" {
		t.Errorf("name = %q", got.Name)
	}
}

func TestHuntList(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	m.Create(ctx, "A", "", "* * * * *", "pb", nil, "self", 0)
	m.Create(ctx, "B", "", "* * * * *", "pb", nil, "self", 0)

	hunts, err := m.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(hunts) != 2 {
		t.Errorf("got %d hunts, want 2", len(hunts))
	}
}

func TestHuntList_FilterActive(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	m.Create(ctx, "A", "", "* * * * *", "pb", nil, "self", 0)
	h, _ := m.Create(ctx, "B", "", "* * * * *", "pb", nil, "self", 0)
	m.Pause(ctx, h.ID)

	active, _ := m.List(ctx, "active")
	if len(active) != 1 {
		t.Errorf("got %d active hunts, want 1", len(active))
	}
}

func TestHuntUpdate(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	h, _ := m.Create(ctx, "Original", "", "* * * * *", "pb1", nil, "self", 0)
	err := m.Update(ctx, h.ID, map[string]any{"name": "Updated", "playbook": "pb2"})
	if err != nil {
		t.Fatal(err)
	}

	got, _ := m.Get(ctx, h.ID)
	if got.Name != "Updated" {
		t.Errorf("name = %q, want Updated", got.Name)
	}
}

func TestHuntDelete(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	h, _ := m.Create(ctx, "To Delete", "", "* * * * *", "pb", nil, "self", 0)
	err := m.Delete(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Get(ctx, h.ID)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestHuntPauseResume(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	h, _ := m.Create(ctx, "Toggle", "", "* * * * *", "pb", nil, "self", 0)

	if err := m.Pause(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get(ctx, h.ID)
	if got.Status != "paused" {
		t.Errorf("status = %q, want paused", got.Status)
	}

	if err := m.Resume(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Get(ctx, h.ID)
	if got.Status != "active" {
		t.Errorf("status = %q, want active", got.Status)
	}
}

func TestHuntDueHunts(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	h, _ := m.Create(ctx, "Due", "", "* * * * *", "pb", nil, "self", 0)
	m.db.ExecContext(ctx, `UPDATE hunts SET next_run = '2000-01-01T00:00:00Z' WHERE id = ?`, h.ID)

	hunts, err := m.DueHunts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(hunts) != 1 {
		t.Errorf("got %d due hunts, want 1", len(hunts))
	}
}

func TestHuntMarkRun(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	h, _ := m.Create(ctx, "Mark", "", "*/5 * * * *", "pb", nil, "self", 0)
	m.MarkRun(ctx, h.ID)

	got, _ := m.Get(ctx, h.ID)
	if got.LastRun == nil {
		t.Error("expected LastRun to be set")
	}
	if got.NextRun == nil {
		t.Error("expected NextRun to be updated")
	}
}

func TestCreate_DuplicateName(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	m.Create(ctx, "Unique", "", "* * * * *", "pb", nil, "self", 0)
	_, err := m.Create(ctx, "Unique", "", "* * * * *", "pb", nil, "self", 0)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

