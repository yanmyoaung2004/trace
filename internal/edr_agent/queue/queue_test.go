package queue

import (
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/edr_agent/monitor"
)

func testEvent(pid int) *monitor.Event {
	return &monitor.Event{
		ID:        "evt",
		AgentID:   "agent-1",
		Type:      "process_create",
		Timestamp: time.Now(),
		Severity:  3,
		Process:   &monitor.ProcessInfo{PID: pid, Name: "powershell.exe"},
	}
}

func TestNew(t *testing.T) {
	q, err := New(t.TempDir(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if q == nil {
		t.Fatal("expected non-nil queue")
	}
}

func TestPush(t *testing.T) {
	q, _ := New(t.TempDir(), 1000)
	defer q.Close()

	if err := q.Push(testEvent(100)); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 1 {
		t.Errorf("len = %d, want 1", q.Len())
	}
}

func TestPopBatch(t *testing.T) {
	q, _ := New(t.TempDir(), 1000)
	defer q.Close()

	q.Push(testEvent(1))
	q.Push(testEvent(2))
	q.Push(testEvent(3))

	events, err := q.PopBatch()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Errorf("got %d events, want 3", len(events))
	}
	if q.Len() != 0 {
		t.Errorf("len = %d, want 0 after pop", q.Len())
	}
}

func TestPushEviction(t *testing.T) {
	q, _ := New(t.TempDir(), 10)
	defer q.Close()

	for i := 0; i < 20; i++ {
		q.Push(testEvent(i))
	}

	if q.Len() > 15 {
		t.Errorf("expected eviction to keep queue small, got %d", q.Len())
	}
}

func TestPopEmpty(t *testing.T) {
	q, _ := New(t.TempDir(), 100)
	defer q.Close()

	events, err := q.PopBatch()
	if err != nil {
		t.Fatal(err)
	}
	if events != nil {
		t.Errorf("expected nil for empty queue, got %d events", len(events))
	}
}

func TestPushPopMultiple(t *testing.T) {
	q, _ := New(t.TempDir(), 1000)
	defer q.Close()

	for i := 0; i < 5; i++ {
		q.Push(testEvent(i))
	}

	events, _ := q.PopBatch()
	if len(events) != 5 {
		t.Fatalf("got %d events, want 5", len(events))
	}

	for _, e := range events {
		if e.ID == "" {
			t.Error("expected non-empty ID after pop")
		}
	}
}

func TestPath(t *testing.T) {
	dir := t.TempDir()
	q, _ := New(dir, 100)
	defer q.Close()

	if q.Path() == "" {
		t.Error("expected non-empty path")
	}
}
