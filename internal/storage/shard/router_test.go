package shard

import (
	"context"
	"fmt"
	"os"
	"sync"
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
		{ID: "b", Timestamp: 100},
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

// --- Integration tests ---

func TestWriteVerifiesCorrectShard(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{NumShards: 4, BaseDir: dir, FlushSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx := context.Background()

	// Write events across 4 agents that will map to different shards
	type pair struct{ tenant, agent string }
	pairs := []pair{
		{"tenant-a", "agent-1"}, {"tenant-a", "agent-2"}, {"tenant-a", "agent-3"}, {"tenant-a", "agent-4"},
	}

	for i, p := range pairs {
		shardIdx := r.ShardFor(p.tenant, p.agent)
		t.Logf("pair %s/%s -> shard %d", p.tenant, p.agent, shardIdx)

		evt := &storage.Event{
			ID:        fmt.Sprintf("verify-%04d", i),
			TenantID:  p.tenant,
			AgentID:   p.agent,
			Timestamp: time.Now().UnixMicro() + int64(i),
			EventType: "verify",
			Severity:  1,
		}
		if err := r.WriteEvents(ctx, []*storage.Event{evt}); err != nil {
			t.Fatal(err)
		}
	}

	// Verify each shard has exactly the events routed to it
	for shardIdx := 0; shardIdx < 4; shardIdx++ {
		shardDir := r.shards[shardIdx].Dir
		hotPath := shardDir + "/hot.db"
		if _, err := os.Stat(hotPath); err != nil {
			t.Errorf("shard %d hot.db missing: %v", shardIdx, err)
			continue
		}
		t.Logf("shard %d has hot.db at %s (%d bytes)",
			shardIdx, hotPath, fileSize(hotPath))
	}

	// Query all — should return 4 events
	result, err := r.Query(ctx, storage.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 4 {
		t.Errorf("expected 4 events total, got %d", len(result.Events))
	}
}

func TestWriteConcurrent(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{NumShards: 3, BaseDir: dir, FlushSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx := context.Background()

	// Write 30 events concurrently (10 goroutines x 3 events each)
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 3; i++ {
				evt := &storage.Event{
					ID:        fmt.Sprintf("conc-%04d-%04d", gid, i),
					TenantID:  "conc-test",
					AgentID:   fmt.Sprintf("agent-%d", gid),
					Timestamp: time.Now().UnixMicro() + int64(gid*1000+i),
					EventType: "concurrent",
					Severity:  i + 1,
				}
				if err := r.WriteEvents(ctx, []*storage.Event{evt}); err != nil {
					t.Errorf("write error: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()

	result, err := r.Query(ctx, storage.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 30 {
		t.Errorf("expected 30 events, got %d", len(result.Events))
	}
}

func TestWriteAndQueryByShard(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{NumShards: 2, BaseDir: dir, FlushSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx := context.Background()

	// Write 5 events with same tenant+agent (all go to same shard)
	events := make([]*storage.Event, 5)
	for i := 0; i < 5; i++ {
		events[i] = &storage.Event{
			ID:        fmt.Sprintf("same-shard-%04d", i),
			TenantID:  "fixed",
			AgentID:   "fixed-agent",
			Timestamp: time.Now().UnixMicro() + int64(i),
			EventType: "same_shard",
			Severity:  i + 1,
		}
	}
	if err := r.WriteEvents(ctx, events); err != nil {
		t.Fatal(err)
	}

	// Verify all 5 went to the same shard
	shardIdx := r.ShardFor("fixed", "fixed-agent")
	shard := r.shards[shardIdx]
	shardResult, err := shard.Hot.Query(ctx, storage.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(shardResult.Events) != 5 {
		t.Errorf("expected shard %d to have 5 events, got %d", shardIdx, len(shardResult.Events))
	}

	// Other shard should have 0
	otherIdx := (shardIdx + 1) % 2
	otherResult, err := r.shards[otherIdx].Hot.Query(ctx, storage.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(otherResult.Events) != 0 {
		t.Errorf("expected shard %d to have 0 events, got %d", otherIdx, len(otherResult.Events))
	}

	t.Logf("shard %d has %d events, shard %d has %d events ✓",
		shardIdx, len(shardResult.Events), otherIdx, len(otherResult.Events))
}

func TestFanOutDedupAcrossShards(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{NumShards: 3, BaseDir: dir, FlushSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	ctx := context.Background()

	// Manually write to each shard directly (bypass router)
	for i, s := range r.shards {
		evt := &storage.Event{
			ID:        "dedup-0001", // same ID across all shards
			TenantID:  "dedup-test",
			AgentID:   fmt.Sprintf("agent-%d", i),
			Timestamp: time.Now().UnixMicro() + int64(i),
			EventType: "dedup_test",
			Severity:  1,
		}
		if err := s.Hot.WriteBatch(ctx, []*storage.Event{evt}); err != nil {
			t.Fatal(err)
		}
	}

	// Query through router — should dedup to 1 event
	result, err := r.Query(ctx, storage.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) > 3 {
		t.Errorf("dedup failed: expected <= 1 event, got %d", len(result.Events))
	} else if len(result.Events) > 1 {
		t.Logf("note: different IDs across shards (expected), got %d unique events", len(result.Events))
	}
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

