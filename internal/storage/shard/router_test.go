package shard

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

func TestNewRouter(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{
		NumShards: 2,
		BaseDir:   dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if r.NumShards() != 2 {
		t.Errorf("expected 2 shards, got %d", r.NumShards())
	}
}

func TestShardFor_Consistent(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{NumShards: 4, BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// Same tenant+agent always maps to same shard
	s1 := r.ShardFor("tenant-a", "agent-1")
	s2 := r.ShardFor("tenant-a", "agent-1")
	if s1 != s2 {
		t.Errorf("expected same shard for same inputs: %d vs %d", s1, s2)
	}
}

func TestShardFor_Distribution(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{NumShards: 4, BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// Different agents should distribute across shards
	shards := make(map[int]int)
	for i := 0; i < 100; i++ {
		agentID := fmt.Sprintf("agent-%d", i)
		s := r.ShardFor("test", agentID)
		shards[s]++
	}

	if len(shards) < 2 {
		t.Errorf("expected distribution across multiple shards, got %d shards used", len(shards))
	}
	t.Logf("shard distribution: %v", shards)
}

func TestWriteRead(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{NumShards: 2, BaseDir: dir, FlushSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx := context.Background()
	events := make([]*storage.Event, 10)
	for i := range events {
		events[i] = &storage.Event{
			ID:        fmt.Sprintf("shard-test-%08d", i),
			TenantID:  "test",
			AgentID:   fmt.Sprintf("agent-%d", i%3),
			Timestamp: time.Now().UnixMicro() + int64(i),
			EventType: "shard_test",
			Severity:  i%5 + 1,
		}
	}

	if err := r.WriteEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	// Query all events
	result, err := r.Query(ctx, storage.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Events) != 10 {
		t.Errorf("expected 10 events, got %d", len(result.Events))
	}
}

func TestWriteRead_SingleShard(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{NumShards: 1, BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx := context.Background()
	events := []*storage.Event{
		{ID: "single-001", TenantID: "t", AgentID: "a", Timestamp: time.Now().UnixMicro(), EventType: "test", Severity: 1},
	}

	if err := r.WriteEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	result, err := r.Query(ctx, storage.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(result.Events))
	}
}

func TestWriteRead_Filtered(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{NumShards: 3, BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx := context.Background()
	for i := 0; i < 20; i++ {
		events := []*storage.Event{
			{
				ID:        fmt.Sprintf("filter-%08d", i),
				TenantID:  "test",
				AgentID:   fmt.Sprintf("agent-%d", i%5),
				Timestamp: time.Now().UnixMicro() + int64(i),
				EventType: "shard_test",
				Severity:  i%5 + 1,
			},
		}
		if err := r.WriteEvents(ctx, events); err != nil {
			t.Fatal(err)
		}
	}

	// Query with agent filter
	result, err := r.Query(ctx, storage.Query{
		AgentIDs: []string{"agent-0"},
		Limit:    100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Error("expected events for agent-0")
	}
}

func TestMergeSortDedup(t *testing.T) {
	events := []*storage.Event{
		{ID: "b", Timestamp: 100},
		{ID: "a", Timestamp: 50},
		{ID: "b", Timestamp: 100}, // duplicate
		{ID: "c", Timestamp: 150},
	}

	result := mergeSortDedupByID(events)
	if len(result) != 3 {
		t.Errorf("expected 3 after dedup, got %d", len(result))
	}
	if result[0].ID != "a" || result[1].ID != "b" || result[2].ID != "c" {
		t.Errorf("wrong order: %v", result)
	}
}
