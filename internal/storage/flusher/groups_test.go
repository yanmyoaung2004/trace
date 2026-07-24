package flusher

import (
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

func TestGroupEvents(t *testing.T) {
	now := time.Now().UnixMicro()
	hourStart := truncateHour(now)

	events := []*storage.Event{
		{TenantID: "tenant-a", Timestamp: now},
		{TenantID: "tenant-a", Timestamp: now + 1000},
		{TenantID: "tenant-b", Timestamp: now},
	}

	groups := groupEvents(events)

	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}

	keyA := groupKey{TenantID: "tenant-a", Hour: hourStart}
	keyB := groupKey{TenantID: "tenant-b", Hour: hourStart}

	if len(groups[keyA]) != 2 {
		t.Errorf("expected 2 events for tenant-a, got %d", len(groups[keyA]))
	}
	if len(groups[keyB]) != 1 {
		t.Errorf("expected 1 event for tenant-b, got %d", len(groups[keyB]))
	}
}

func TestGroupEvents_SameTenantDifferentHours(t *testing.T) {
	hour1 := truncateHour(time.Now().UnixMicro())
	hour2 := hour1 + int64(time.Hour/time.Microsecond)

	events := []*storage.Event{
		{TenantID: "test", Timestamp: hour1 + 100},
		{TenantID: "test", Timestamp: hour2 + 100},
	}

	groups := groupEvents(events)

	if len(groups) != 2 {
		t.Errorf("expected 2 groups for different hours, got %d", len(groups))
	}
}

func TestTruncateHour(t *testing.T) {
	ts := time.Date(2026, 7, 24, 15, 30, 45, 0, time.UTC).UnixMicro()
	truncated := truncateHour(ts)
	expected := time.Date(2026, 7, 24, 15, 0, 0, 0, time.UTC).UnixMicro()

	if truncated != expected {
		t.Errorf("expected %d, got %d", expected, truncated)
	}
}

func TestEstimateSize(t *testing.T) {
	events := []*storage.Event{
		{ID: "id-1", TenantID: "t", AgentID: "a", EventType: "test"},
		{ID: "id-2", TenantID: "t", AgentID: "a", EventType: "test"},
	}

	size := estimateSize(events)
	if size <= 0 {
		t.Errorf("expected positive size, got %d", size)
	}
}

func TestReadyGroups(t *testing.T) {
	now := time.Now().UnixMicro()
	hourStart := truncateHour(now)

	// Create a group with many events to exceed target size
	events := make([]*storage.Event, 10000)
	for i := range events {
		events[i] = &storage.Event{
			ID:       "id",
			TenantID: "tenant-a",
			AgentID:  "agent",
			Timestamp: now,
		}
	}

	groups := map[groupKey][]*storage.Event{
		{TenantID: "tenant-a", Hour: hourStart}: events,
	}

	ready := readyGroups(groups, 100) // small target
	if len(ready) != 1 {
		t.Errorf("expected 1 ready group, got %d", len(ready))
	}
}
