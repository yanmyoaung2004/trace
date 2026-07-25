package cold

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
)

func writeBenchFile(tb testing.TB, dir string, n int, rowGroupSize int) string {
	tb.Helper()
	opts := parquet.DefaultParquetOptions()
	if rowGroupSize > 0 {
		opts.RowGroupSize = rowGroupSize
	}
	pw := parquet.NewParquetWriter(
		filepath.Join(dir, "temp"),
		filepath.Join(dir, "out"),
		opts,
	)

	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	events := make([]*storage.Event, n)
	for i := 0; i < n; i++ {
		events[i] = &storage.Event{
			ID:        fmt.Sprintf("bench-%08d", i),
			TenantID:  "bench",
			AgentID:   fmt.Sprintf("agent-%03d", i%100),
			Timestamp: now.Add(time.Duration(i) * time.Second).UnixMicro(),
			EventType: "benchmark",
			Severity:  i%5 + 1,
		}
	}

	res, err := pw.WriteBatch(context.Background(), events, "bench/2026-07-01/00")
	if err != nil {
		tb.Fatal(err)
	}
	pw.Close()
	return res.Path
}

func BenchmarkColdReader_FullScan(b *testing.B) {
	dir := b.TempDir()
	path := writeBenchFile(b, dir, 10000, 100)

	r := NewParquetReader()
	files := []storage.FileInfo{{Path: path}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := r.QueryFiles(context.Background(), files, storage.Query{Limit: 10000})
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Events) == 0 {
			b.Fatal("expected events")
		}
	}
}

func BenchmarkColdReader_TimeRangePruned(b *testing.B) {
	dir := b.TempDir()
	path := writeBenchFile(b, dir, 10000, 100)

	r := NewParquetReader()
	files := []storage.FileInfo{{Path: path}}

	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	since := now.Add(100 * time.Second).UnixMicro()
	until := now.Add(200 * time.Second).UnixMicro()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := r.QueryFiles(context.Background(), files, storage.Query{
			SinceUs: since,
			UntilUs: until,
			Limit:   10000,
		})
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Events) == 0 {
			b.Fatal("expected events")
		}
	}
}

func BenchmarkColdReader_AgentPruned(b *testing.B) {
	dir := b.TempDir()
	path := writeBenchFile(b, dir, 10000, 100)

	r := NewParquetReader()
	files := []storage.FileInfo{{Path: path}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := r.QueryFiles(context.Background(), files, storage.Query{
			AgentIDs: []string{"agent-000", "agent-001"},
			Limit:    10000,
		})
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Events) == 0 {
			b.Fatal("expected events")
		}
	}
}

func BenchmarkColdReader_NarrowTimeRange(b *testing.B) {
	dir := b.TempDir()
	// 100K events with 500 rows per row group = 200 row groups
	path := writeBenchFile(b, dir, 100000, 500)

	r := NewParquetReader()
	files := []storage.FileInfo{{Path: path}}

	// Query for a 5-second window in the middle (0.5% of data)
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	since := now.Add(50000 * time.Second).UnixMicro()
	until := now.Add(50005 * time.Second).UnixMicro()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := r.QueryFiles(context.Background(), files, storage.Query{
			SinceUs: since,
			UntilUs: until,
			Limit:   100000,
		})
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Events) == 0 {
			b.Fatal("expected events")
		}
	}
}

func BenchmarkColdReader_SeverityPruned(b *testing.B) {
	dir := b.TempDir()
	path := writeBenchFile(b, dir, 10000, 100)

	r := NewParquetReader()
	files := []storage.FileInfo{{Path: path}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := r.QueryFiles(context.Background(), files, storage.Query{
			MinSeverity: 5,
			Limit:       10000,
		})
		if err != nil {
			b.Fatal(err)
		}
		if len(result.Events) == 0 {
			b.Fatal("expected events")
		}
	}
}
