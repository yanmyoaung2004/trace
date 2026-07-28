package harness

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/cold"
	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	"github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
	"github.com/yanmyoaung2004/trace/internal/storage/router"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

func BenchmarkHotStoreWriteThroughput(b *testing.B) {
	dir := b.TempDir()
	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer hot.Close()

	ctx := context.Background()
	batchSize := 1000
	events := make([]*storage.Event, batchSize)
	for i := 0; i < batchSize; i++ {
		events[i] = &storage.Event{
			ID:        fmt.Sprintf("load-%d", i),
			TenantID:  "load-test",
			AgentID:   "agent",
			Timestamp: time.Now().UnixMicro(),
			EventType: "load_test",
			Severity:  1,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := hot.WriteBatch(ctx, events); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHotStoreQueryThroughput(b *testing.B) {
	dir := b.TempDir()
	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer hot.Close()

	ctx := context.Background()

	// Write 50K events
	numEvents := 50000
	batchSize := 1000
	for offset := 0; offset < numEvents; offset += batchSize {
		end := offset + batchSize
		if end > numEvents {
			end = numEvents
		}
		events := make([]*storage.Event, 0, end-offset)
		for i := offset; i < end; i++ {
			events = append(events, &storage.Event{
				ID:        fmt.Sprintf("q-%d", i),
				TenantID:  "load-test",
				AgentID:   fmt.Sprintf("agent-%d", i%10),
				Timestamp: time.Now().UnixMicro() + int64(i),
				EventType: "load_test",
				Severity:  i%5 + 1,
			})
		}
		if err := hot.WriteBatch(ctx, events); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := hot.Query(ctx, storage.Query{Limit: 1000})
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Events) == 0 {
			b.Fatal("expected events")
		}
	}
}

func BenchmarkPipeline_WriteFlush(b *testing.B) {
	dir := b.TempDir()
	pw := parquet.NewParquetWriter(
		filepath.Join(dir, "temp"),
		filepath.Join(dir, "events"),
		parquet.DefaultParquetOptions(),
	)
	defer pw.Close()

	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer hot.Close()

	m, err := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer m.Close()

	f := flusher.NewFlusher(hot, m, pw, 0, 100, 10000, filepath.Join(dir, "events"))

	ctx := context.Background()
	batchSize := 100
	events := make([]*storage.Event, batchSize)
	for i := 0; i < batchSize; i++ {
		events[i] = &storage.Event{
			ID:        fmt.Sprintf("pipeline-bench-%d", i),
			TenantID:  "bench",
			AgentID:   fmt.Sprintf("agent-%d", i%5),
			Timestamp: time.Now().UnixMicro() + int64(i),
			EventType: "bench",
			Severity:  1,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := hot.WriteBatch(ctx, events); err != nil {
			b.Fatal(err)
		}
		if err := f.FlushNow(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPipeline_WriteFlushRead(b *testing.B) {
	dir := b.TempDir()
	pw := parquet.NewParquetWriter(
		filepath.Join(dir, "temp"),
		filepath.Join(dir, "events"),
		parquet.DefaultParquetOptions(),
	)
	defer pw.Close()

	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer hot.Close()

	m, err := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer m.Close()

	f := flusher.NewFlusher(hot, m, pw, 0, 100, 10000, filepath.Join(dir, "events"))
	cr := cold.NewParquetReader()
	r := router.NewRouter(hot, cr, m)

	ctx := context.Background()
	batchSize := 100
	events := make([]*storage.Event, batchSize)
	for i := 0; i < batchSize; i++ {
		events[i] = &storage.Event{
			ID:        fmt.Sprintf("pipeline-bench-%d", i),
			TenantID:  "bench",
			AgentID:   fmt.Sprintf("agent-%d", i%5),
			Timestamp: time.Now().UnixMicro() + int64(i),
			EventType: "bench",
			Severity:  1,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := hot.WriteBatch(ctx, events); err != nil {
			b.Fatal(err)
		}
		if err := f.FlushNow(ctx); err != nil {
			b.Fatal(err)
		}
		result, err := r.Query(ctx, storage.Query{Limit: batchSize})
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Events) == 0 {
			b.Fatal("expected events from pipeline")
		}
	}
}

func TestPipeline_10kEventsThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	dir := t.TempDir()
	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer hot.Close()

	m, err := manifest.NewManifest(filepath.Join(dir, "manifest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	ctx := context.Background()
	numEvents := 10000
	batchSize := 1000

	start := time.Now()

	for offset := 0; offset < numEvents; offset += batchSize {
		end := offset + batchSize
		if end > numEvents {
			end = numEvents
		}
		events := make([]*storage.Event, 0, end-offset)
		for i := offset; i < end; i++ {
			events = append(events, &storage.Event{
				ID:        fmt.Sprintf("stress-%08d", i),
				TenantID:  "stress",
				AgentID:   fmt.Sprintf("agent-%d", i%20),
				Timestamp: time.Now().UnixMicro() + int64(i),
				EventType: "stress_test",
				Severity:  i%5 + 1,
			})
		}
		if err := hot.WriteBatch(ctx, events); err != nil {
			t.Fatalf("batch %d: %v", offset/batchSize, err)
		}
	}

	elapsed := time.Since(start)
	throughput := float64(numEvents) / elapsed.Seconds()

	t.Logf("Wrote %d events in %v (%.0f events/sec)", numEvents, elapsed, throughput)

	// Verify all events are queryable
	result, err := hot.Query(ctx, storage.Query{Limit: numEvents + 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != numEvents {
		t.Errorf("expected %d events, got %d", numEvents, len(result.Events))
	}

	// Target: >10K events/sec (limited by SQLite variable count per multi-row INSERT)
	if throughput < 10000 {
		t.Errorf("throughput below target: %.0f events/sec (target: 10000)", throughput)
	}
}

func TestPipeline_100kEventsLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy load test in short mode")
	}

	dir := t.TempDir()
	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer hot.Close()

	ctx := context.Background()
	numEvents := 100000
	batchSize := 1000
	numBatches := numEvents / batchSize

	start := time.Now()

	for batch := 0; batch < numBatches; batch++ {
		events := make([]*storage.Event, batchSize)
		for i := 0; i < batchSize; i++ {
			idx := batch*batchSize + i
			events[i] = &storage.Event{
				ID:        fmt.Sprintf("heavy-%08d", idx),
				TenantID:  "heavy",
				AgentID:   fmt.Sprintf("agent-%d", idx%50),
				Timestamp: start.UnixMicro() + int64(idx),
				EventType: "heavy_test",
				Severity:  idx%5 + 1,
			}
		}
		if err := hot.WriteBatch(ctx, events); err != nil {
			t.Fatalf("batch %d: %v", batch, err)
		}
	}

	elapsed := time.Since(start)
	throughput := float64(numEvents) / elapsed.Seconds()

	t.Logf("Wrote %d events in %v (%.0f events/sec)", numEvents, elapsed, throughput)

	// Verify with multiple queries
	result, err := hot.Query(ctx, storage.Query{Limit: 5000, MinSeverity: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Error("expected events with severity >= 3")
	}

	result2, err := hot.Query(ctx, storage.Query{AgentIDs: []string{"agent-0"}, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(result2.Events) == 0 {
		t.Error("expected events for agent-0")
	}
}

func TestPipeline_500kEventsHighThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping high-throughput load test in short mode")
	}

	dir := t.TempDir()
	hot, err := sqlite.NewSQLiteHotStore(filepath.Join(dir, "hot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer hot.Close()

	ctx := context.Background()
	numEvents := 500000
	batchSize := 50
	numBatches := numEvents / batchSize

	allEvents := make([][]*storage.Event, numBatches)
	for batch := 0; batch < numBatches; batch++ {
		events := make([]*storage.Event, batchSize)
		for i := 0; i < batchSize; i++ {
			idx := batch*batchSize + i
			events[i] = &storage.Event{
				ID:        fmt.Sprintf("hload-%08d", idx),
				TenantID:  "hload",
				AgentID:   fmt.Sprintf("agent-%d", idx%100),
				Timestamp: time.Now().UnixMicro() + int64(idx),
				EventType: "high_load",
				Severity:  idx%5 + 1,
			}
		}
		allEvents[batch] = events
	}

	start := time.Now()

	for batch := 0; batch < numBatches; batch++ {
		if err := hot.WriteBatch(ctx, allEvents[batch]); err != nil {
			t.Fatalf("batch %d: %v", batch, err)
		}
	}

	elapsed := time.Since(start)
	throughput := float64(numEvents) / elapsed.Seconds()

	t.Logf("Wrote %d events in %v (%.0f events/sec)", numEvents, elapsed, throughput)

	result, err := hot.Query(ctx, storage.Query{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) == 0 {
		t.Error("expected events to be queryable")
	}

	if throughput < 100000 {
		t.Errorf("throughput below target: %.0f events/sec (target: 100000)", throughput)
	}
}
